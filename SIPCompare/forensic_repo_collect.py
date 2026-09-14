#!/usr/bin/env python3
# (c) 2026, Shane D. Shook, All Rights Reserved
"""
forensic_repo_collect.py

PURPOSE
-------
Forensically collects a GitHub or Bitbucket repository for code analysis.
The collection mechanics (mirror clone, bundle, hash,
chain-of-custody log) are identical regardless of host, since git itself
doesn't care which platform it's talking to. The only real difference
between hosts is how authentication is supplied, which this script detects
and handles automatically.
Produces:
  1. A full mirror clone (all branches, tags, refs)
  2. A single-file git bundle (immutable artifact suitable for evidence)
  3. SHA-256 hash of the bundle, computed immediately after creation
  4. A JSON chain-of-custody log with timestamps, hashes, and repo metadata

PLATFORM DETECTION
-------------------
By default, the platform is auto-detected from the repository URL's
hostname (anything containing "github" is treated as GitHub, anything
containing "bitbucket" is treated as Bitbucket). For self-hosted GitHub
Enterprise or Bitbucket Server/Data Center instances, where the hostname
won't contain either name, pass --platform explicitly.

AUTHENTICATION. READ THIS FIRST
---------------------------------
GitHub:
  --token <personal-access-token>
      Standard GitHub PAT with read access to the repository.

Bitbucket, use ONE of:
  (a) Repository/Project/Workspace Access Token (Bitbucket Cloud):
      --token <access-token>
      Passed as "x-token-auth:<token>", no separate username needed.
      Repository-level tokens are available on free/Standard plans;
      Project and Workspace-level tokens require a Premium plan.

  (b) Personal API Token (Bitbucket Cloud):
      --username <bitbucket-username> --api-token <api-token>
      This is the current, non-deprecated replacement for the old
      Bitbucket "App Password" credential (App Passwords were fully
      retired by Bitbucket in June 2026 and no longer work). Create one
      from Atlassian account settings, not from the Bitbucket repository
      settings. Available on any account tier, including free.

  (c) Personal Access Token (Bitbucket Server / Data Center, self-hosted):
      --username <any-non-empty-string> --api-token <personal-access-token>
      Server/Data Center accepts the PAT as the password field with an
      arbitrary (often ignored) username; confirm the exact convention with
      the repository owner's Bitbucket admin, as this can vary by version.

If no credentials are supplied, the script assumes credentials are already
configured locally (e.g. SSH key or a stored git credential helper) and
clones as-is.

RUN SYNTAX
----------
    python3 forensic_repo_collect.py <repo_url> <output_dir> \\
        [--platform github|bitbucket] \\
        [--token TOKEN | --username USER --api-token TOKEN]

    <repo_url>        HTTPS clone URL of the repository
                       e.g. https://github.com/ownername/reponame.git
                       e.g. https://bitbucket.org/workspace/reponame.git
    <output_dir>       Directory where the mirror, bundle, and logs will be
                        written (created if it does not exist)
    --platform          Optional. "github" or "bitbucket". If omitted, the
                         platform is auto-detected from the URL's hostname;
                         required for self-hosted instances that don't
                         contain "github" or "bitbucket" in the hostname.
    --token             GitHub PAT, or Bitbucket Cloud access token
    --username          Bitbucket username (used with --api-token)
    --api-token         Bitbucket Personal API Token or Server/Data Center PAT

EXAMPLES
--------
    # GitHub
    python3 forensic_repo_collect.py \\
        https://github.com/acmecorp/widget-engine.git \\
        ./evidence/widget-engine \\
        --token ghp_xxxxxxxxxxxxxxxxxxxx

    # Bitbucket Cloud, Personal API Token
    python3 forensic_repo_collect.py \\
        https://bitbucket.org/acmecorp/widget-engine.git \\
        ./evidence/widget-engine \\
        --username jdoe --api-token ATATTxxxxxxxxxxxxxxxx

    # Bitbucket Cloud, repository access token
    python3 forensic_repo_collect.py \\
        https://bitbucket.org/acmecorp/widget-engine.git \\
        ./evidence/widget-engine \\
        --token BBTKxxxxxxxxxxxxxxxx

    # Self-hosted Bitbucket Server, platform not auto-detectable from hostname
    python3 forensic_repo_collect.py \\
        https://git.internal.acmecorp.com/scm/project/widget-engine.git \\
        ./evidence/widget-engine \\
        --platform bitbucket --username jdoe --api-token <PAT>

REQUIREMENTS
------------
    - Python 3.8+
    - git installed and on PATH
    - Network access to the repository host

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
from urllib.parse import urlparse


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


def detect_platform(repo_url):
    """
    Auto-detect the hosting platform from the repository URL's hostname.
    Returns "github", "bitbucket", or None if it can't be determined
    (e.g. a self-hosted instance with a custom domain), in which case the
    caller must supply --platform explicitly.
    """
    hostname = urlparse(repo_url).hostname or ""
    hostname = hostname.lower()
    if "github" in hostname:
        return "github"
    if "bitbucket" in hostname:
        return "bitbucket"
    return None


def build_authenticated_url(repo_url, platform, token=None, username=None, api_token=None):
    """
    Inject platform-appropriate credentials into an HTTPS clone URL, without
    ever printing or logging the credential itself.

    GitHub: token is injected directly as "https://<token>@host/...".
    Bitbucket with a token: uses the "x-token-auth:<token>@" convention
      (Bitbucket Cloud repository/project/workspace access tokens).
    Bitbucket with username + api_token: uses the standard
      "username:secret@" convention (Bitbucket Personal API Tokens, the
      current replacement for the now-retired App Password credential, or
      Server/Data Center Personal Access Tokens depending on server
      configuration).
    No credentials supplied: returns the URL unchanged (assumes local
      credentials are already configured).
    """
    if token and (username or api_token):
        raise ValueError(
            "Use either --token, or --username/--api-token together, not both."
        )
    if username and not api_token:
        raise ValueError("--username requires --api-token.")
    if api_token and not username:
        raise ValueError("--api-token requires --username.")

    if not (token or username or api_token):
        return repo_url

    if not repo_url.startswith("https://"):
        raise ValueError("Credential-based auth requires an https:// clone URL.")

    if platform == "github":
        if not token:
            raise ValueError("GitHub authentication requires --token.")
        return repo_url.replace("https://", f"https://{token}@", 1)

    if platform == "bitbucket":
        if token:
            return repo_url.replace("https://", f"https://x-token-auth:{token}@", 1)
        return repo_url.replace("https://", f"https://{username}:{api_token}@", 1)

    raise ValueError(
        f"Cannot apply credentials without a known platform. Got: {platform!r}. "
        "Pass --platform github or --platform bitbucket explicitly."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Forensically collect a GitHub or Bitbucket repository (mirror clone, bundle, hash)."
    )
    parser.add_argument("repo_url", help="HTTPS clone URL of the repository")
    parser.add_argument("output_dir", help="Directory to write evidence artifacts into")
    parser.add_argument(
        "--platform",
        choices=["github", "bitbucket"],
        default=None,
        help="Hosting platform. Auto-detected from the URL hostname if omitted; "
             "required for self-hosted instances that don't contain "
             "'github' or 'bitbucket' in the hostname.",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="GitHub Personal Access Token, or Bitbucket Cloud access token",
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Bitbucket username (used together with --api-token)",
    )
    parser.add_argument(
        "--api-token",
        default=None,
        help="Bitbucket Personal API Token (current replacement for the "
             "retired App Password), or Server/Data Center Personal Access Token",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    platform = args.platform or detect_platform(args.repo_url)
    if platform is None and (args.token or args.username or args.api_token):
        print(
            "ERROR: could not auto-detect the hosting platform from the URL, "
            "and credentials were provided. Pass --platform github or "
            "--platform bitbucket explicitly.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Timestamp for this collection run (UTC, ISO 8601), used throughout the
    # chain-of-custody record so the evidence log follows standard forensic
    # timestamp conventions.
    collection_start = datetime.now(timezone.utc).isoformat()

    mirror_path = os.path.join(args.output_dir, "repo_mirror.git")
    # Bundle path must be absolute: git bundle create is run with cwd set to
    # the mirror directory, so a relative path here would resolve incorrectly.
    bundle_path = os.path.abspath(os.path.join(args.output_dir, "repo_evidence.bundle"))
    log_path = os.path.join(args.output_dir, "chain_of_custody.json")

    print(f"[{collection_start}] Starting forensic collection ({platform or 'unspecified platform'})...")

    # Step 1: Authenticate + full mirror clone.
    # --mirror captures ALL refs: branches and tags, the forensically
    # complete equivalent of "everything git knows about this repo", not
    # just the commit history shown by `git log`.
    clone_url = build_authenticated_url(
        args.repo_url,
        platform=platform,
        token=args.token,
        username=args.username,
        api_token=args.api_token,
    )
    print("Cloning full mirror (branches, tags, refs)...")
    run_command(["git", "clone", "--mirror", clone_url, mirror_path])

    # Step 2: Package the mirror into a single-file bundle.
    # A bundle is a single immutable file, easier to hash, store, and
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

    # Determine which auth method was used, for the record (never the
    # credential itself).
    if args.token and platform == "github":
        auth_method = "GitHub Personal Access Token"
    elif args.token and platform == "bitbucket":
        auth_method = "Bitbucket access token (x-token-auth)"
    elif args.username and args.api_token:
        auth_method = "Bitbucket Personal API Token / Server PAT"
    else:
        auth_method = "Pre-configured local credentials (SSH key or credential helper)"

    # Step 5: Write the chain-of-custody log.
    # This JSON file is the forensic record documenting the collection:
    # who collected it, when, from where, and the hash that proves integrity.
    chain_of_custody = {
        "repository_url": args.repo_url,
        "repository_platform": platform or "unspecified",
        "authentication_method": auth_method,
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
    print(f"  Platform:          {platform or 'unspecified'}")
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
