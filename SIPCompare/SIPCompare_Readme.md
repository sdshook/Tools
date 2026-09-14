# SIPCompare: Forensic Code Similarity Analysis Tool

© 2025 Shane D. Shook, All Rights Reserved

## Overview

SIPCompare detects software intellectual property theft and code plagiarism using AI models, multi-dimensional analysis, and statistical validation to provide court-admissible evidence across 15+ programming languages.

SIPCompare uses a single analytical approach, exact-content matching combined with structural, syntactic, and semantic similarity scoring, to determine whether Company B's code was copied, altered, or otherwise misused from Company A's. That same analysis applies at two scopes:
- **Snapshot mode**: examines two codebases as they exist today.
- **History mode**: examines the full commit histories of two collected repositories, applying the identical analysis across every point in time rather than just the current state.

History mode is often the more telling of the two, since theft frequently shows up as a single large or contextually revealing commit rather than a gradual drift. It establishes not just similarity but precedence (who had the code first) and, when it exists, the exact commit where copied code entered Company B's repository.

**Key Capabilities**: Multi-dimensional similarity detection, obfuscation resistance, automatic cross-language detection, statistical validation (p < 0.05), forensic-quality evidence packages with complete chain of custody, and commit-history precedence analysis.

## AI Models & Performance

| Model | Speed | Accuracy | Best Use Case | Memory | Detection Rate |
|-------|-------|----------|---------------|--------|----------------|
| **graphcodebert** | Medium | **Highest** | **Forensic Analysis** | Medium | 90-100% |
| **codet5** | Slow | High | Cross-Language Detection | High | 90-95% |
| **mini** | **Fast** | Good | Large Repositories (1000+ files) / History Screening | **Low** | 85-90% |

**Obfuscation Resistance**: 94-96% detection despite code modifications, including renamed function/variable/parameter names.
**Statistical Rigor**: p < 0.05 significance, < 5% false positive rate

All three models require reaching Hugging Face (`huggingface.co`) to download pretrained weights the first time they're used. In an offline or firewalled environment, SIPCompare degrades gracefully to token, structural, and control-flow analysis (all still fully functional via tree-sitter) rather than crashing, but semantic similarity will read `0.0` until the models can actually download.

## Installation & Usage

**Requirements**: Python 3.8+, PyTorch, Transformers, git (for history mode)

```bash
# Install dependencies
pip install numpy scipy tqdm sentence-transformers transformers torch
pip install tree-sitter==0.21.3 tree-sitter-languages==1.10.2
```

> **Version note**: `tree-sitter` releases newer than `0.21.x` change an internal API that `tree-sitter-languages` (as of 1.10.2) doesn't yet support, and will fail at import with `TypeError: __init__() takes exactly 1 argument (2 given)`. Pin `tree-sitter==0.21.3` as shown above until `tree-sitter-languages` publishes a compatible update.

### Two subcommands

SIPCompare now has two subcommands instead of one flat invocation: `snapshot` (compare two codebases as they exist now, the original workflow) and `history` (compare two repositories' full commit histories). Run `python SIPCompare.py snapshot --help` or `python SIPCompare.py history --help` for the complete option list of each.

### Usage Examples: snapshot mode

```bash
# Standard forensic analysis
python SIPCompare.py snapshot --repoA /path/to/suspected --repoB /path/to/original \
                     --threshold 0.6 --embedding-model graphcodebert \
                     --parallel 4 --output evidence.zip
```

**Key options**: `--repoA`/`--repoB` (required directory paths), `--threshold` (0-1, default: 0.50), `--embedding-model` (mini/graphcodebert/codet5), `--parallel` (processes, default: 1), `--output` (evidence filename), `--no-statistical`, `--verbose`. Cross-language pairs are detected automatically by file extension and weighted accordingly. There is no separate flag for it, it is a standard part of every comparison.

### Usage Examples: history mode

History mode takes a `.bundle` file or a mirror directory on each side. This is the output of a forensic repository collection step (from GitHub, Bitbucket, or any other git-based host), not a plain checked-out directory. It runs in two phases:

- **Phase 1 (exact-content match)**: git content-hashes every file version ("blob") across each repository's ENTIRE history. Any hash shared between the two histories means byte-identical code existed on both sides at some point, and git can identify the exact commit, author, and timestamp it first appeared on each side, establishing precedence (who had it first) independent of filenames or renames.
- **Phase 2 (fuzzy match on a targeted commit selection)**: runs the full similarity engine (the same one snapshot mode uses) against a bounded set of historical commit snapshots. By default this selection is DERIVED from Phase 1: whatever files got flagged as exact matches are traced through their own history on each side, so Phase 2 specifically looks for a later, quietly modified or variable-renamed revision of code that started out as an exact copy. If Phase 1 finds nothing (or `--history-mode fuzzy-only` is used), it falls back to evenly time-sampling commits across each full history.

```bash
# Full history comparison: exact match + targeted fuzzy match
python SIPCompare.py history --repoA client_repo.bundle --repoB competitor_repo.bundle \
                     --output-dir ./history_analysis --threshold 0.6

# Exact-content match only (fast, no fuzzy pass, good first screen)
python SIPCompare.py history --repoA a.bundle --repoB b.bundle \
                     --output-dir ./out --history-mode exact-only

# Hand-pick specific commits instead of automatic selection
python SIPCompare.py history --repoA a.bundle --repoB b.bundle \
                     --output-dir ./out --commitsA <hash1>,<hash2> --commitsB <hash3>,<hash4>
```

**Key options**: `--repoA`/`--repoB` (required, bundle file or mirror directory), `--output-dir` (required), `--history-mode` (`exact-only`/`fuzzy-only`/`both`, default: `both`), `--threshold` (default: 0.6), `--embedding-model` (default: `mini`, for speed across many commit pairs, raise to `graphcodebert` for a final single high-confidence pair), `--extensions`, `--min-blob-size`, `--commitsA`/`--commitsB`, `--max-commits-per-side` (default: 15), `--max-pairs` (safety cap on total comparisons, default: 200, requires `--force` to exceed).

**History mode output**: `phase1_exact_matches.json` (shared content + precedence), `phase2_commit_selection.json` (which commits were compared and why), `phase2_similarity_timeline.csv` (one row per commit pair, with match counts and average similarity), and `phase2_runs/<commitA>_vs_<commitB>/evidence_package.zip` (a full forensic evidence package per compared pair, same format as snapshot mode's output).

## Supported Languages

**Full Support**: Python, Java, C/C++, JavaScript, TypeScript, Go, Rust, C#, PHP, Ruby, Swift, Kotlin, Scala
**Semantic Only**: Shell Scripts, PowerShell

## Clone Detection & Evidence

| Clone Type | Description | Evidence Level |
|------------|-------------|----------------|
| **Type 1** | Exact clones (whitespace/comments differ) | STRONG (>0.95) |
| **Type 2** | Renamed identifiers (including function parameters) | STRONG (>0.85) |
| **Type 3** | Near-miss (added/deleted statements) | MODERATE (>0.75) |
| **Type 4** | Semantic clones (different syntax, same function) | MODERATE (>0.65) |

The four clone types above are classified primarily by syntactic signal (token overlap) and semantic signal (embedding similarity). Structural similarity, meaning the shape of the code's control flow, function signatures, and variable declarations independent of identifier names, is a third, separate analytical dimension SIPCompare measures alongside those two. It will usually move together with a syntactic or semantic clone finding, since copied code typically keeps its underlying shape even when identifiers are changed, but it is computed independently and is what actually confirms a Type 2 (renamed-identifier) clone: token similarity alone can be fooled by a thorough rename, while structural similarity cannot, since identifiers are canonicalized before comparison at both the token level and the structural (control-flow/function-signature/variable-declaration) level. In practice, structural agreement is the strongest single piece of evidence that two files share a common origin, regardless of what their identifiers or exact syntax look like.

**Evidence Package Contents**: Interactive HTML report, CSV/JSON data, executive summary, source code snapshots, chain of custody documentation with hash verification and complete audit trail for court admissibility. In history mode, this is generated per compared commit pair, in addition to the overall exact-match and timeline reports.

## Troubleshooting & Performance

**Common Issues**:
- **"No processable files found"**: Check file extensions and repository paths.
- **"Model loading failed"** / semantic_similarity always reads `0.0`: `sentence-transformers`/`transformers` install fine from PyPI, but loading the actual pretrained weights requires reaching `huggingface.co` the first time. Confirm outbound network access to that host; SIPCompare will otherwise run in degraded (token/structural/control-flow only) mode without crashing.
- **`TypeError: __init__() takes exactly 1 argument (2 given)`** on startup: `tree-sitter`/`tree-sitter-languages` version mismatch. See the version note under Installation.
- **"Out of memory"**: Reduce parallel workers, use `mini` model, process smaller batches (snapshot mode), or lower `--max-commits-per-side` / `--max-pairs` (history mode).
- **History mode: "would run N comparisons, exceeding --max-pairs"**: narrow the commit selection (`--commitsA`/`--commitsB`, or a smaller `--max-commits-per-side`) or pass `--force` if the larger run is intentional.

**Optimization**:
- **Large repositories (snapshot mode)**: `--parallel 8 --embedding-model mini`
- **High accuracy (snapshot mode)**: `--threshold 0.6 --embedding-model graphcodebert`
- **Cross-language pairs (snapshot mode)**: `--embedding-model codet5` (weighting adjusts automatically, no flag needed)
- **Large histories (history mode)**: run `--history-mode exact-only` first as a fast screen, then a targeted `--history-mode fuzzy-only` pass with `--commitsA`/`--commitsB` on the commits that matter.
