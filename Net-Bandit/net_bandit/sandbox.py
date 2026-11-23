"""Validation and execution of compiled judgment entries.

Entries are small Python functions written by the analysis model. They are
restricted to an allowlisted subset of Python (checked on the AST), run with
no builtins except an allowlist, and are stopped after an opcode budget.

SECURITY NOTE: this is defence in depth for a proof of concept, not a real
sandbox. A production agent should execute entries out of process (a
restricted child process, a WebAssembly runtime, or a separate signed
service) and require entries to be signed by a quorum before use.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import hmac
import re
import sys
import time
from collections import OrderedDict

from .events import VERDICTS, account_class, basename, ip_category, win_path_bucket

ENTRY_FILENAME = "<arc-entry>"
MAX_CODE_CHARS = 8000
MAX_LINES = 120
MAX_INT = 10**6
MAX_STR = 2000
MAX_OPCODES = 200_000
MAX_SECONDS = 0.25


class EntryError(Exception):
    pass


class EntryTimeout(EntryError):
    pass


# --------------------------------------------------------------------------
# Helpers available to entries
# --------------------------------------------------------------------------

_rx_cache: dict[str, re.Pattern] = {}


def _rx(pattern: str) -> re.Pattern:
    pattern = str(pattern)[:200]
    rx = _rx_cache.get(pattern)
    if rx is None:
        rx = re.compile(pattern, re.IGNORECASE)
        if len(_rx_cache) < 512:
            _rx_cache[pattern] = rx
    return rx


def re_search(pattern, text) -> bool:
    return _rx(pattern).search(str(text or "")[:4096]) is not None


def re_match(pattern, text) -> bool:
    return _rx(pattern).match(str(text or "")[:4096]) is not None


def re_findall(pattern, text) -> list:
    return _rx(pattern).findall(str(text or "")[:4096])[:50]


def contains_any(text, needles) -> bool:
    t = str(text or "").lower()
    return any(str(n).lower() in t for n in list(needles)[:100])


def path_under(path, prefix) -> bool:
    p = str(path or "").strip('"').replace("/", "\\").lower()
    q = str(prefix or "").replace("/", "\\").lower()
    return bool(q) and p.startswith(q)


SAFE_FUNCS = {
    "len": len, "any": any, "all": all, "min": min, "max": max, "sorted": sorted,
    "set": set, "list": list, "tuple": tuple, "dict": dict, "str": str, "int": int,
    "float": float, "bool": bool, "abs": abs, "round": round,
    "re_search": re_search, "re_match": re_match, "re_findall": re_findall,
    "contains_any": contains_any, "path_under": path_under,
    "win_path_bucket": win_path_bucket, "account_class": account_class,
    "ip_category": ip_category, "basename": basename,
}

SAFE_METHODS = {
    "lower", "upper", "casefold", "strip", "lstrip", "rstrip", "startswith", "endswith",
    "split", "rsplit", "replace", "find", "count", "join", "get", "items", "keys",
    "values", "isdigit", "partition", "rpartition",
}

ALLOWED_NODES = {
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Return, ast.If, ast.IfExp,
    ast.Assign, ast.AugAssign, ast.For, ast.Break, ast.Continue, ast.Pass, ast.Expr,
    ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub, ast.BinOp, ast.Add,
    ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.FloorDiv, ast.Compare, ast.Eq, ast.NotEq,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot, ast.Call,
    ast.keyword, ast.Name, ast.Load, ast.Store, ast.Constant, ast.Attribute,
    ast.Subscript, ast.Slice, ast.List, ast.Tuple, ast.Dict, ast.Set, ast.ListComp,
    ast.SetComp, ast.GeneratorExp, ast.comprehension, ast.JoinedStr, ast.FormattedValue,
}


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

MAX_NESTING = 20


def _max_depth(code: str) -> int:
    """Bracket nesting depth, ignoring string literals (cheap pre-parse guard)."""
    depth = best = 0
    quote = None
    prev = ""
    for ch in code:
        if quote:
            if ch == quote and prev != "\\":
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
            best = max(best, depth)
        elif ch in ")]}":
            depth = max(0, depth - 1)
        prev = ch
    return best


def validate(code: str) -> list[str]:
    """Return a list of problems; an empty list means the entry is acceptable."""
    # Size limits are checked BEFORE parsing: ast.parse of hostile input (huge or deeply
    # nested) can exhaust memory or recursion in the main process.
    if not isinstance(code, str):
        return ["code must be a string"]
    if len(code) > MAX_CODE_CHARS:
        return ["code too long"]
    if code.count("\n") > MAX_LINES:
        return ["too many lines"]
    if _max_depth(code) > MAX_NESTING:
        return ["too deeply nested"]
    errs: list[str] = []
    try:
        tree = ast.parse(code, filename=ENTRY_FILENAME)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        return [f"unparseable: {type(e).__name__}"]

    body = [n for n in tree.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
    if len(body) != 1 or not isinstance(body[0], ast.FunctionDef) or body[0].name != "judge":
        errs.append("module must contain exactly one top-level function: def judge(e)")
        return errs
    fn = body[0]
    a = fn.args
    if fn.decorator_list or a.vararg or a.kwarg or a.kwonlyargs or a.defaults or a.posonlyargs or len(a.args) != 1:
        errs.append("judge must take exactly one positional argument and have no decorators")
        return errs

    allowed_names = set(SAFE_FUNCS) | {a.args[0].arg}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            allowed_names.add(node.id)

    fdefs = 0
    for node in ast.walk(tree):
        t = type(node)
        if t not in ALLOWED_NODES:
            errs.append(f"construct not allowed: {t.__name__} (line {getattr(node, 'lineno', '?')})")
            continue
        if t is ast.FunctionDef:
            fdefs += 1
        elif t is ast.Name:
            if node.id.startswith("_"):
                errs.append(f"name not allowed: {node.id}")
            elif isinstance(node.ctx, ast.Load) and node.id not in allowed_names:
                errs.append(f"unknown name: {node.id}")
        elif t is ast.Attribute:
            if node.attr.startswith("_") or node.attr not in SAFE_METHODS:
                errs.append(f"attribute not allowed: .{node.attr}")
        elif t is ast.Call:
            f = node.func
            if isinstance(f, ast.Name):
                if f.id not in SAFE_FUNCS:
                    errs.append(f"call not allowed: {f.id}()")
            elif not isinstance(f, ast.Attribute):
                errs.append("only named helpers and allowlisted methods may be called")
        elif t is ast.Constant:
            v = node.value
            if isinstance(v, int) and not isinstance(v, bool) and abs(v) > MAX_INT:
                errs.append("integer constant too large")
            elif isinstance(v, (str, bytes)) and len(v) > MAX_STR:
                errs.append("string constant too long")
        elif t is ast.BinOp and isinstance(node.op, ast.Mult):
            for side in (node.left, node.right):
                if isinstance(side, ast.BinOp) and isinstance(side.op, ast.Mult):
                    errs.append("chained multiplication not allowed")
    if fdefs != 1:
        errs.append("nested functions are not allowed")
    return sorted(set(errs))


# --------------------------------------------------------------------------
# Compilation and execution
# --------------------------------------------------------------------------

MAX_COMPILED = 256  # LRU bound on compiled entries kept in memory
_compiled: "OrderedDict[str, object]" = OrderedDict()


def code_sha(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def compile_entry(code: str):
    sha = code_sha(code)
    fn = _compiled.get(sha)
    if fn is not None:
        _compiled.move_to_end(sha)
        return fn
    errs = validate(code)
    if errs:
        raise EntryError("; ".join(errs))
    g = {"__builtins__": {}, **SAFE_FUNCS}
    exec(compile(code, ENTRY_FILENAME, "exec"), g)  # noqa: S102 - validated above
    fn = g["judge"]
    _compiled[sha] = fn
    if len(_compiled) > MAX_COMPILED:
        _compiled.popitem(last=False)
    return fn


def _normalize(out) -> dict:
    if not isinstance(out, dict):
        raise EntryError("entry must return a dict")
    verdict = out.get("verdict")
    if verdict not in VERDICTS:
        raise EntryError(f"bad verdict: {verdict!r}")
    try:
        conf = float(out.get("confidence", 0.0))
    except (TypeError, ValueError):
        raise EntryError("bad confidence")
    return {
        "verdict": verdict,
        "confidence": max(0.0, min(1.0, conf)),
        "reason": str(out.get("reason", ""))[:300],
    }


def run_entry(fn, event: dict) -> dict:
    """Run an entry on a copy of the event, under an opcode and time budget."""
    count = [0]
    start = time.perf_counter()

    def local(frame, what, arg):
        if what in ("opcode", "line"):
            count[0] += 1
            if count[0] > MAX_OPCODES or (count[0] % 1000 == 0 and time.perf_counter() - start > MAX_SECONDS):
                raise EntryTimeout("entry exceeded its execution budget")
        return local

    def glob(frame, what, arg):
        if frame.f_code.co_filename == ENTRY_FILENAME:
            frame.f_trace_opcodes = True
            return local
        return None

    old = sys.gettrace()
    sys.settrace(glob)
    try:
        out = fn(copy.deepcopy(event))
    except EntryError:
        raise
    except Exception as e:  # any runtime error inside an entry is an entry failure
        raise EntryError(f"{type(e).__name__}: {e}") from None
    finally:
        sys.settrace(old)
    return _normalize(out)


# --------------------------------------------------------------------------
# Integrity
# --------------------------------------------------------------------------

def sign(key: bytes, code: str) -> str:
    return hmac.new(key, code.encode(), hashlib.sha256).hexdigest()


def verify(key: bytes, code: str, sig: str) -> bool:
    return hmac.compare_digest(sign(key, code), sig or "")
