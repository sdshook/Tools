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

## Authentication

**GitHub**: `--token <personal-access-token>`, a standard GitHub PAT with read access.

**Bitbucket**, use one of:

- **Repository access token** (simplest): `--token <access-token>`. Create it from the repository's own Settings > Access tokens page, selecting only **Read** permission on the Repositories scope. Available on free/Standard plans.
- **Personal API Token**: `--username <bitbucket-username> --api-token <api-token>`. This is the current replacement for Bitbucket's old "App Password" credential, which was fully retired in June 2026 and no longer works.
  1. Go to Atlassian account settings, Security tab, "Create and manage API tokens" (not the Bitbucket repository or workspace settings).
  2. Click **"Create API token with scopes"**, not the plain "Create API token" button. The plain button creates an unscoped token that authenticates but fails on every git operation with a generic "you may not have access" error.
  3. Select **Bitbucket** as the app.
  4. Select the `read:repository:bitbucket` scope. This tool only ever reads (clones), so no write scope is needed or should be granted.
  5. Generate. New tokens can take up to a minute to start working.

  `--username` must be your actual Bitbucket username, not your email and not your display name. Find it at `bitbucket.org/account/settings/`, under "Bitbucket profile settings", labeled "Username". This is confirmed by live testing against a real Bitbucket repository; some Atlassian documentation suggests email works here, it did not in practice for `git clone`.

## Note

The script hashes the bundle right after it's created. Any time the bundle is copied or transferred afterward, it should be re-hashed and compared against the value in `chain_of_custody.json` to confirm nothing changed in transit.

## Using SIPCompare to review collected bundles

SIPCompare's `snapshot` and `history` subcommands both accept a `.bundle` file or a bare mirror directory directly, alongside an ordinary checkout directory. The steps below apply to git bundles produced by this script; the same general approach (verify, then analyze) applies to other version-control export formats where the equivalent option exists.

### Step 1: Verify each bundle before use

Confirm the bundle's SHA-256 hash still matches the value recorded in its `chain_of_custody.json` before doing anything else. This preserves the chain of custody, confirming the artifact being analyzed is the exact one that was collected, not a copy that changed in transit.

```
sha256sum repo_evidence.bundle
```

Compare the output against the `bundle_sha256` field in the corresponding `chain_of_custody.json`. Stop and re-collect if they don't match.

### Step 2: Run SIPCompare directly against the two bundles

For a single-point-in-time comparison:

```
python SIPCompare.py snapshot --repoA repo_A_evidence.bundle --repoB repo_B_evidence.bundle --threshold 0.75 --embedding-model graphcodebert --output evidence_package.zip
```

By default this extracts `HEAD` from each bundle. To compare a specific branch, tag, or point-in-time commit on either side, use `--refA`/`--refB`:

```
python SIPCompare.py snapshot --repoA repo_A_evidence.bundle --repoB repo_B_evidence.bundle --refA main --refB feature/renamed-copy
```

For a full commit-history comparison instead of a single snapshot, use `history` mode on the same two bundles:

```
python SIPCompare.py history --repoA repo_A_evidence.bundle --repoB repo_B_evidence.bundle --output-dir ./history_analysis --threshold 0.6
```

Adjust `--threshold`, `--embedding-model`, and `--parallel` as needed. See `python SIPCompare.py snapshot --help` and `python SIPCompare.py history --help` for the full option list of each.

### Step 3: Review the evidence package

SIPCompare writes `evidence_package.zip` (snapshot mode) or a set of reports per compared commit pair (history mode), containing:

- `reports/executive_summary.txt`, a plain-language conclusion and risk assessment
- `reports/technical_analysis.txt`, methodology, clone-type breakdown, transformation patterns
- `reports/forensic_report.html`, a detailed per-match report with diffs
- `reports/detailed_analysis.csv` / `reports/analysis_data.json`, structured match data
- `chain_of_custody.txt`, SIPCompare's own custody record for the comparison run

### Step 4: Document the full chain

For the record, note:

- The bundle SHA-256 hashes verified in Step 1
- The ref used on each side, if something other than the default `HEAD`
- The SIPCompare parameters and output package hash

This ties the original collection (this script's `chain_of_custody.json`) to the comparison analysis (SIPCompare's evidence package) into one traceable record, from original repository through to forensic conclusion.

---
(c) 2026, Shane D. Shook, All Rights Reserved
