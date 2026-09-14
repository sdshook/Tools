# Readme for forensic_repo_collect.py

(c) 2026, Shane D. Shook, All Rights Reserved

A Python script that forensically collects a GitHub or Bitbucket repository for code analysis.

## What it does

1. **Authenticates and clones a full mirror** of the target repository, capturing every branch, tag, and ref, not just what `git log` would show.
2. **Packages the mirror into a single-file git bundle**, a self-contained, immutable artifact that's easy to store and transfer.
3. **Computes a SHA-256 hash of the bundle** immediately after creation.
4. **Writes a chain-of-custody log** (JSON) recording the repository URL, platform, authentication method, timestamps, the SHA-256 hash, the HEAD commit, the total number of refs captured, and the collection method used.

Platform is auto-detected from the repository URL's hostname (GitHub or Bitbucket). For self-hosted instances where the hostname doesn't contain either name, pass `--platform` explicitly.

## Output

Running the script produces three items in the specified output directory:

- `repo_mirror.git`, the working mirror clone
- `repo_evidence.bundle`, the single-file evidentiary artifact
- `chain_of_custody.json`, the custody record

## Usage

```
python3 forensic_repo_collect.py <repo_url> <output_dir> \
    [--platform github|bitbucket] \
    [--token TOKEN | --username USER --api-token TOKEN]
```

See the comment header inside the script for full run syntax, authentication options for each platform, examples, and requirements.

## Note

The script hashes the bundle right after it's created. Any time the bundle is copied or transferred afterward, it should be re-hashed and compared against the value in `chain_of_custody.json` to confirm nothing changed in transit.

## Using SIPCompare to review collected bundles

SIPCompare analyzes source files on disk. It does not read `.bundle` files, mirror clones, or other packed VCS formats directly. Before running SIPCompare, materialize each side into an ordinary working-tree checkout. The steps below apply to git bundles produced by this script; the same general approach (checkout, verify, compare) applies to other version-control export formats with the equivalent checkout command substituted.

### Step 1: Verify each bundle before use

Confirm the bundle's SHA-256 hash still matches the value recorded in its `chain_of_custody.json` before doing anything else. This preserves the chain of custody, confirming the artifact being analyzed is the exact one that was collected, not a copy that changed in transit.

```
sha256sum repo_evidence.bundle
```

Compare the output against the `bundle_sha256` field in the corresponding `chain_of_custody.json`. Stop and re-collect if they don't match.

### Step 2: Clone a working tree from each bundle

```
git clone repo_A_evidence.bundle repo_A_checkout
git clone repo_B_evidence.bundle repo_B_checkout
```

Each command produces an ordinary source directory (not a `.git` mirror) that SIPCompare can walk and parse.

### Step 3: Check out the specific ref or commit in question (if needed)

A bundle clone checks out whichever ref was `HEAD` at collection time. If the analysis turns on a specific branch, tag, or point-in-time commit, check that out explicitly on each side and record which ref was used:

```
cd repo_A_checkout && git checkout <branch-or-commit>
cd ../repo_B_checkout && git checkout <branch-or-commit>
```

### Step 4: Run SIPCompare against the two checkouts

```
python SIPCompare.py snapshot --repoA ./repo_A_checkout --repoB ./repo_B_checkout --threshold 0.75 --embedding-model graphcodebert --output evidence_package.zip
```

Adjust `--threshold`, `--embedding-model`, and `--parallel` as needed. See `python SIPCompare.py snapshot --help` for the full option list, and `python SIPCompare.py history --help` for comparing full commit histories directly from the two bundles instead of a single-snapshot checkout.

### Step 5: Review the evidence package

SIPCompare writes `evidence_package.zip`, containing:

- `reports/executive_summary.txt`, a plain-language conclusion and risk assessment
- `reports/technical_analysis.txt`, methodology, clone-type breakdown, transformation patterns
- `reports/forensic_report.html`, a detailed per-match report with diffs
- `reports/detailed_analysis.csv` / `reports/analysis_data.json`, structured match data
- `chain_of_custody.txt`, SIPCompare's own custody record for the comparison run

### Step 6: Document the full chain

For the record, note:

- The bundle SHA-256 hashes verified in Step 1
- The exact ref/commit checked out in Step 3 (if applicable)
- The SIPCompare parameters and output package hash

This ties the original collection (this script's `chain_of_custody.json`) to the comparison analysis (SIPCompare's `evidence_package.zip`) into one traceable record, from original repository through to forensic conclusion.

---
(c) 2026, Shane D. Shook, All Rights Reserved
