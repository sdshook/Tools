"""Near-miss retrieval over class templates (advisory only).

Similarity never decides a verdict. It is used to:
  - give Claude the closest known classes as context when the cache misses
  - score novelty: how far a new class is from everything already known

Token-set Jaccard over the abstracted templates: no embedding model, no extra
CPU or memory pressure. Linear scan per kind is fine for thousands of classes;
swap in MinHash/LSH if a host ever learns far more.
"""
from __future__ import annotations

import re
from collections import OrderedDict

_TOK = re.compile(r"<[a-z0-9_]+>|[a-z0-9_.\-]+")


def tokens(template: dict) -> frozenset:
    out = set()
    for k, v in template.items():
        if k == "kind":
            continue
        for t in _TOK.findall(str(v).lower()):
            out.add(f"{k}:{t}")
    return frozenset(out)


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


class ClassIndex:
    def __init__(self, max_per_kind: int = 5000):
        self.max_per_kind = max_per_kind
        self.by_kind: dict[str, OrderedDict] = {}

    def add(self, key: str, template: dict, summary: dict) -> None:
        bucket = self.by_kind.setdefault(template.get("kind", ""), OrderedDict())
        bucket[key] = (tokens(template), summary)
        bucket.move_to_end(key)
        if len(bucket) > self.max_per_kind:
            bucket.popitem(last=False)

    def nearest(self, template: dict, k: int = 3, min_sim: float = 0.3, exclude: str | None = None):
        q = tokens(template)
        scored = []
        for key, (toks, summary) in self.by_kind.get(template.get("kind", ""), {}).items():
            if key == exclude:
                continue
            s = jaccard(q, toks)
            if s >= min_sim:
                scored.append((s, key, summary))
        scored.sort(key=lambda x: -x[0])
        return scored[:k]

    def novelty(self, template: dict, exclude: str | None = None) -> float:
        """1.0 = unlike any known class of this kind; 0.0 = identical to one."""
        best = self.nearest(template, k=1, min_sim=0.0, exclude=exclude)
        return round(1.0 - best[0][0], 3) if best else 1.0
