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

---
(c) 2026, Shane D. Shook, All Rights Reserved
