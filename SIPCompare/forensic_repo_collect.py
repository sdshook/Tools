#!/usr/bin/env python3
# (c) 2026, Shane D. Shook, All Rights Reserved
"""
forensic_repo_collect.py

PURPOSE
-------
Forensically collects a GitHub repository for expert-witness / litigation use.
Produces:
  1. A full mirror clone (all branches, tags, refs, reflog)
  2. A single-file git bundle (immutable artifact suitable for evidence)
  3. SHA-256 hashes of the bundle, computed immediately after creation
  4. A JSON chain-of-custody log with timestamps, hashes, and repo metadata

RUN SYNTAX
----------
    python3 forensic_repo_collect.py <repo_url> <output_dir> [--token TOKEN]

    <repo_url>    HTTPS clone URL of the repository
                  e.g. https://github.com/ownername/reponame.git
    <output_dir>  Directory where the mirror, bundle, and logs will be written
                  (will be created if it does not exist)
    --token       Optional. A GitHub Personal Access Token with read access,
                  provided by the repository owner. If omitted,
                  the script assumes credentials are already configured
                  (e.g. via git credential manager or SSH key).

EXAMPLE
-------
    python3 forensic_repo_collect.py \\
        https://github.com/acmecorp/widget-engine.git \\
        ./evidence/widget-engine \\
        --token ghp_xxxxxxxxxxxxxxxxxxxx

REQUIREMENTS
------------
    - Python 3.8+
    - git installed and on PATH
    - Network access to github.com

NOTE ON CHAIN OF CUSTODY
-------------------------
This script hashes the bundle immediately after it is written, and again
after any copy step you perform manually (not automated here, since transfer
method varies by case). Always verify the second hash matches the first
before relying on a transferred copy as evidence.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def run_command(cmd, cwd=None):
    """Run a subprocess command, capturing output, and raise on failure."""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
    return result.stdout.strip()


def sha256_of_file(filepath):
    """Compute SHA-256 hash of a file, reading in chunks to handle large repos."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_authenticated_url(repo_url, token):
    """
    Inject a token into an HTTPS GitHub URL for authenticated cloning,
    without ever printing or logging the token itself.
    """
    if not token:
        return repo_url
    if not repo_url.startswith("https://"):
        raise ValueError("Token-based auth requires an https:// clone URL.")
    return repo_url.replace("https://", f"https://{token}@", 1)


def main():
    parser = argparse.ArgumentParser(
        description="Forensically collect a GitHub repository (mirror clone, bundle, hash)."
    )
    parser.add_argument("repo_url", help="HTTPS clone URL of the repository")
    parser.add_argument("output_dir", help="Directory to write evidence artifacts into")
    parser.add_argument(
        "--token",
        default=None,
        help="Optional GitHub Personal Access Token for authentication",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Timestamp for this collection run (UTC, ISO 8601) — used throughout the
    # chain-of-custody record so the evidence log matches courtroom-friendly
    # timestamp conventions.
    collection_start = datetime.now(timezone.utc).isoformat()

    mirror_path = os.path.join(args.output_dir, "repo_mirror.git")
    # Bundle path must be absolute: git bundle create is run with cwd set to
    # the mirror directory, so a relative path here would resolve incorrectly.
    bundle_path = os.path.abspath(os.path.join(args.output_dir, "repo_evidence.bundle"))
    log_path = os.path.join(args.output_dir, "chain_of_custody.json")

    print(f"[{collection_start}] Starting forensic collection...")

    # Step 1: Authenticate + full mirror clone.
    # --mirror captures ALL refs: branches, tags, and the reflog — this is the
    # forensically complete equivalent of "everything git knows about this repo",
    # not just the commit history shown by `git log`.
    clone_url = build_authenticated_url(args.repo_url, args.token)
    print("Cloning full mirror (branches, tags, refs)...")
    run_command(["git", "clone", "--mirror", clone_url, mirror_path])

    # Step 2: Package the mirror into a single-file bundle.
    # A bundle is a single immutable file — easier to hash, store, and
    # transfer than a directory of git internals.
    print("Creating git bundle (single-file evidentiary artifact)...")
    run_command(["git", "bundle", "create", bundle_path, "--all"], cwd=mirror_path)

    # Step 3: Hash the bundle immediately after creation.
    print("Computing SHA-256 hash of bundle...")
    bundle_hash = sha256_of_file(bundle_path)
    hash_timestamp = datetime.now(timezone.utc).isoformat()

    # Step 4: Capture basic repo metadata for the record (last commit, ref count).
    # This is informational context for the chain-of-custody log, not a
    # substitute for the hash itself.
    try:
        head_commit = run_command(["git", "rev-parse", "HEAD"], cwd=mirror_path)
    except RuntimeError:
        head_commit = "UNKNOWN"

    try:
        ref_list = run_command(["git", "show-ref"], cwd=mirror_path)
        ref_count = len(ref_list.splitlines()) if ref_list else 0
    except RuntimeError:
        ref_count = "UNKNOWN"

    # Step 5: Write the chain-of-custody log.
    # This JSON file is the record you'd attach to your expert declaration:
    # who collected it, when, from where, and the hash that proves integrity.
    chain_of_custody = {
        "repository_url": args.repo_url,
        "collection_start_utc": collection_start,
        "hash_computed_utc": hash_timestamp,
        "bundle_file": os.path.abspath(bundle_path),
        "bundle_sha256": bundle_hash,
        "head_commit": head_commit,
        "total_refs_captured": ref_count,
        "collection_method": "git clone --mirror; git bundle create --all",
        "hash_algorithm": "SHA-256",
        "notes": (
            "Re-hash this bundle immediately after any transfer to another "
            "party or storage medium, and confirm the hash matches the "
            "value recorded here before relying on the copy as evidence."
        ),
    }

    with open(log_path, "w") as f:
        json.dump(chain_of_custody, f, indent=2)

    print("\nCollection complete.")
    print(f"  Bundle:            {bundle_path}")
    print(f"  SHA-256:           {bundle_hash}")
    print(f"  Chain-of-custody:  {log_path}")
    print("\nRe-hash the bundle after transfer and compare to the value above.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
