# forensic_repo_collect.py

A Python script that forensically collects a GitHub repository for expert-witness / litigation use.

## What it does

1. **Authenticates and clones a full mirror** of the target repository — every branch, tag, and ref, not just what `git log` would show.
2. **Packages the mirror into a single-file git bundle**, a self-contained, immutable artifact that's easy to store and transfer.
3. **Computes a SHA-256 hash of the bundle** immediately after creation.
4. **Writes a chain-of-custody log** (JSON) recording the repository URL, timestamps, the SHA-256 hash, the HEAD commit, the total number of refs captured, and the method used.

## Output

Running the script produces three items in the specified output directory:

- `repo_mirror.git` — the working mirror clone
- `repo_evidence.bundle` — the single-file evidentiary artifact
- `chain_of_custody.json` — the custody record

## Usage

```
python3 forensic_repo_collect.py <repo_url> <output_dir> [--token TOKEN]
```

See the comment header inside the script for full run syntax, an example, and requirements.

## Note

The script hashes the bundle right after it's created. Any time the bundle is copied or transferred afterward, it should be re-hashed and compared against the value in `chain_of_custody.json` to confirm nothing changed in transit.

## Using SIPCompare to review competing bundles (or other VCS trees)

SIPCompare analyzes source files on disk — it does not read `.bundle` files, mirror clones, or other packed VCS formats directly. Before running SIPCompare, materialize each side into an ordinary working-tree checkout. The steps below apply to git bundles produced by this script; the same general approach (checkout → verify → compare) applies to other version-control export formats (e.g., Mercurial bundles, SVN dumps) with the equivalent checkout command substituted.

### Step 1 — Verify each bundle before use

Confirm the bundle's SHA-256 hash still matches the value recorded in its `chain_of_custody.json` before doing anything else. This preserves the evidentiary chain — you want to know you're analyzing the exact artifact that was collected, not a copy that changed in transit.

```
sha256sum repo_evidence.bundle
```

Compare the output against the `bundle_sha256` field in the corresponding `chain_of_custody.json`. Stop and re-collect if they don't match.

### Step 2 — Clone a working tree from each bundle

```
git clone repo_evidence.bundle client_repo_checkout
git clone opposing_evidence.bundle opposing_repo_checkout
```

Each command produces an ordinary source directory (not a `.git` mirror) that SIPCompare can walk and parse.

### Step 3 — Check out the specific ref or commit in question (if needed)

A bundle clone checks out whichever ref was `HEAD` at collection time. If the matter turns on a specific branch, tag, or point-in-time commit (e.g., "the code as of the date of departure"), check that out explicitly on each side and record which ref was used:

```
cd client_repo_checkout && git checkout <branch-or-commit>
cd ../opposing_repo_checkout && git checkout <branch-or-commit>
```

### Step 4 — Run SIPCompare against the two checkouts

```
python SIPCompare.py --repoA ./client_repo_checkout --repoB ./opposing_repo_checkout --threshold 0.75 --embedding-model graphcodebert --output evidence_package.zip
```

Adjust `--threshold`, `--embedding-model`, `--parallel`, and `--cross-language` as appropriate to the matter. See SIPCompare's own `--help` output or header comment for the full option list.

### Step 5 — Review the evidence package

SIPCompare writes `evidence_package.zip`, containing:

- `reports/executive_summary.txt` — plain-language conclusion and risk assessment
- `reports/technical_analysis.txt` — methodology, clone-type breakdown, transformation patterns
- `reports/forensic_report.html` — detailed per-match report with diffs
- `reports/detailed_analysis.csv` / `reports/analysis_data.json` — structured match data
- `chain_of_custody.txt` — SIPCompare's own custody record for the comparison run

### Step 6 — Document the full chain

For the record, note in your case file:

- The bundle SHA-256 hashes verified in Step 1
- The exact ref/commit checked out in Step 3 (if applicable)
- The SIPCompare version, parameters, and output package hash

This ties the original collection (this script's `chain_of_custody.json`) to the comparison analysis (SIPCompare's `evidence_package.zip`) into one traceable record, from original repository through to forensic conclusion.

---
(c) 2026, Shane D. Shook, All Rights Reserved
