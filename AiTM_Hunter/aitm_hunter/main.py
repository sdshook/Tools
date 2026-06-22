"""
CLI orchestrator.

    python -m aitm_hunter.main search      --query "o365 login" --out results/o365.json
    python -m aitm_hunter.main fingerprint --input results/o365.json --out results/o365_fp.json
    python -m aitm_hunter.main deepcrawl   --input results/o365_fp.json --out results/o365_deep.json --i-have-read-safety-md
    python -m aitm_hunter.main report      --input results/o365_deep.json --out results/o365_report.csv
    python -m aitm_hunter.main evilginx    --url "https://suspicious.com" --out results/evilginx.json
    python -m aitm_hunter.main malvertising --query "o365 login" --out results/ads.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aitm_hunter import search as search_mod
from aitm_hunter import triage as triage_mod
from aitm_hunter import fingerprint as fingerprint_mod
from aitm_hunter import deepcrawl as deepcrawl_mod
from aitm_hunter import report as report_mod
from aitm_hunter import evilginx as evilginx_mod
from aitm_hunter import malvertising as malvertising_mod
from aitm_hunter import signatures


def cmd_search(args: argparse.Namespace) -> None:
    if args.manual_input:
        results = search_mod.load_manual_results(args.manual_input)
        query_desc = f"manual input: {args.manual_input}"
    else:
        if not args.query:
            print("Error: --query is required when not using --manual-input", file=sys.stderr)
            sys.exit(1)
        results = search_mod.search_serpapi(args.query, num_results=args.num_results)
        query_desc = f"query: {args.query!r}"

    print(f"Found {len(results)} SERP results for {query_desc}", file=sys.stderr)

    brand_domains = triage_mod.DEFAULT_BRAND_DOMAINS
    if args.brand:
        unknown = [b for b in args.brand if b not in triage_mod.DEFAULT_BRAND_DOMAINS]
        if unknown:
            known = ", ".join(sorted(triage_mod.DEFAULT_BRAND_DOMAINS))
            print(
                f"Warning: unknown brand(s) {unknown} -- no entry in "
                f"DEFAULT_BRAND_DOMAINS (edit triage.py to add them). "
                f"Known brands: {known}",
                file=sys.stderr,
            )
        brand_domains = {
            b: triage_mod.DEFAULT_BRAND_DOMAINS[b]
            for b in args.brand
            if b in triage_mod.DEFAULT_BRAND_DOMAINS
        }

    triaged_records = []
    for r in results:
        t = triage_mod.triage_url(r.actual_url, brand_domains=brand_domains)
        merged = report_mod.merge_record(r, t)
        triaged_records.append(merged)
        flag = "  <-- SUSPICIOUS" if t.risk_score >= 50 else ""
        print(f"  [{t.risk_score:3d}] {r.result_type:8s} {r.actual_url}{flag}", file=sys.stderr)

    report_mod.write_json_report(triaged_records, args.out)
    print(f"\nWrote {len(triaged_records)} triaged records to {args.out}", file=sys.stderr)
    print(report_mod.summarize(triaged_records), file=sys.stderr)


def cmd_fingerprint(args: argparse.Namespace) -> None:
    """Run TLS/behavioral fingerprinting on triaged results."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    try:
        records = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    threshold = args.risk_threshold
    candidates = [r for r in records if r.get("risk_score", 0) >= threshold]
    
    print(
        f"Fingerprinting {len(candidates)} of {len(records)} records "
        f"(risk >= {threshold})...",
        file=sys.stderr,
    )
    
    fingerprinted_records = []
    for rec in candidates:
        url = rec.get("final_url") or rec.get("original_url", "")
        brand = rec.get("typosquat_target", "")
        
        print(f"  Fingerprinting: {url}", file=sys.stderr)
        fp_result = fingerprint_mod.fingerprint_url(
            url, 
            brand=brand,
            check_tls=not args.skip_tls,
            check_proxy_behavior=not args.skip_proxy_check,
        )
        
        # Merge fingerprint results into record
        merged = dict(rec)
        merged["fingerprint_risk_score"] = fp_result.fingerprint_risk_score
        merged["fingerprint_risk_reasons"] = fp_result.fingerprint_risk_reasons
        merged["is_likely_aitm"] = fp_result.is_likely_aitm
        merged["is_likely_static_phish"] = fp_result.is_likely_static_phish
        merged["signature_matches"] = [
            {"type": m[0], "hash": m[1], "kit": m[2]} 
            for m in fp_result.signature_matches
        ]
        if fp_result.tls_info:
            merged["tls_version"] = fp_result.tls_info.tls_version
            merged["cert_issuer"] = fp_result.tls_info.cert_issuer
            merged["cert_subject"] = fp_result.tls_info.cert_subject
        merged["fingerprint_error"] = fp_result.error
        
        # Update combined risk score
        merged["risk_score"] = min(
            rec.get("risk_score", 0) + fp_result.fingerprint_risk_score, 
            100
        )
        merged["risk_reasons"] = rec.get("risk_reasons", []) + fp_result.fingerprint_risk_reasons
        
        flag = ""
        if fp_result.is_likely_aitm:
            flag = " <-- LIKELY AiTM"
        elif fp_result.is_likely_static_phish:
            flag = " <-- LIKELY STATIC PHISH"
        elif fp_result.signature_matches:
            flag = f" <-- SIGNATURE MATCH: {fp_result.signature_matches[0][2]}"
        print(f"    [{merged['risk_score']:3d}]{flag}", file=sys.stderr)
        
        fingerprinted_records.append(merged)
    
    # Include non-fingerprinted (below threshold) records unchanged
    skipped = [r for r in records if r.get("risk_score", 0) < threshold]
    
    report_mod.write_json_report(fingerprinted_records + skipped, args.out)
    print(
        f"\nWrote {len(fingerprinted_records)} fingerprinted + "
        f"{len(skipped)} skipped records to {args.out}",
        file=sys.stderr,
    )


def cmd_deepcrawl(args: argparse.Namespace) -> None:
    if not args.i_have_read_safety_md:
        print(
            "Refusing to run deepcrawl without --i-have-read-safety-md.\n"
            "Read SAFETY.md first -- this stage renders live malicious pages "
            "in a real browser and must run from an isolated, disposable host.",
            file=sys.stderr,
        )
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    try:
        records = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    threshold = args.risk_threshold
    candidates = [r for r in records if r.get("risk_score", 0) >= threshold]
    print(
        f"{len(candidates)} of {len(records)} records meet risk threshold "
        f">= {threshold}; deep-crawling those only.",
        file=sys.stderr,
    )

    urls = [r.get("final_url") or r.get("original_url", "") for r in candidates]
    results = deepcrawl_mod.deep_crawl_batch(
        urls, args.artifact_dir, i_have_read_safety_md=True
    )

    by_url = {r.url: r for r in results}
    merged_records = []
    for rec in candidates:
        url = rec.get("final_url") or rec.get("original_url", "")
        dc = by_url.get(url)
        merged = dict(rec)
        if dc:
            merged["screenshot_path"] = dc.screenshot_path
            merged["har_path"] = dc.har_path
            merged["deepcrawl_error"] = dc.error
        merged_records.append(merged)

    skipped = [r for r in records if r.get("risk_score", 0) < threshold]
    report_mod.write_json_report(merged_records + skipped, args.out)
    print(f"Wrote {len(merged_records)} deep-crawled + {len(skipped)} skipped records to {args.out}", file=sys.stderr)


def cmd_report(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    try:
        records = json.loads(input_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    if args.out.endswith(".csv"):
        report_mod.write_csv_report(records, args.out)
    else:
        report_mod.write_json_report(records, args.out)
    print(f"Wrote report to {args.out}", file=sys.stderr)
    print(report_mod.summarize(records, threshold=args.risk_threshold), file=sys.stderr)


def cmd_evilginx(args: argparse.Namespace) -> None:
    """Run Evilginx-specific detection on URLs."""
    urls = []
    
    if args.url:
        urls.append(args.url)
    
    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        try:
            records = json.loads(input_path.read_text())
            for r in records:
                url = r.get("final_url") or r.get("actual_url") or r.get("url", "")
                if url:
                    urls.append(url)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
            sys.exit(1)
    
    if not urls:
        print("Error: Provide --url or --input with URLs to analyze", file=sys.stderr)
        sys.exit(1)
    
    print(f"Running Evilginx detection on {len(urls)} URL(s)...", file=sys.stderr)
    
    results = []
    for url in urls:
        print(f"\n  Analyzing: {url}", file=sys.stderr)
        result = evilginx_mod.detect_evilginx(url, deep_check=not args.quick)
        results.append(result.to_dict())
        
        status = "🚨 EVILGINX" if result.is_evilginx else "✓ Clean"
        print(f"    [{result.risk_score:3d}] {status} (confidence: {result.confidence})", file=sys.stderr)
        if result.markers_found:
            print(f"    Markers: {result.markers_found}", file=sys.stderr)
        if result.ioc_match:
            print(f"    IOC Match: {result.ioc_match.get('notes', 'Known malicious')}", file=sys.stderr)
    
    # Write results
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nWrote {len(results)} results to {args.out}", file=sys.stderr)
    
    # Summary
    evilginx_count = sum(1 for r in results if r.get('is_evilginx'))
    print(f"Evilginx detected: {evilginx_count}/{len(results)}", file=sys.stderr)


def cmd_malvertising(args: argparse.Namespace) -> None:
    """Search for malvertising in sponsored ads."""
    if not args.query:
        print("Error: --query is required", file=sys.stderr)
        sys.exit(1)
    
    print(f"Searching for malvertising: '{args.query}'", file=sys.stderr)
    print("Sources: ", end="", file=sys.stderr)
    
    use_bing_api = args.bing_api and (
        args.bing_api_key or 
        __import__('os').environ.get('BING_ADS_API_KEY') or
        __import__('os').environ.get('BING_SEARCH_API_KEY')
    )
    
    if use_bing_api:
        print("Bing API + ", end="", file=sys.stderr)
    print("Browser scraping (Google + Bing)", file=sys.stderr)
    
    try:
        ads = malvertising_mod.scrape_ads_all_sources(
            args.query,
            use_bing_api=use_bing_api,
            headless=not args.visible,
        )
    except RuntimeError as e:
        if "Playwright" in str(e):
            print(f"\nError: {e}", file=sys.stderr)
            print("Browser scraping requires Playwright. Install with:", file=sys.stderr)
            print("  pip install playwright && playwright install chromium", file=sys.stderr)
            sys.exit(1)
        raise
    
    # Convert to dicts
    results = [ad.to_dict() for ad in ads]
    
    # Write results
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    
    suspicious = [ad for ad in ads if ad.is_suspicious]
    
    print(f"\nTotal ads found: {len(ads)}", file=sys.stderr)
    print(f"Suspicious ads: {len(suspicious)}", file=sys.stderr)
    
    if suspicious:
        print("\n🚨 Suspicious Ads:", file=sys.stderr)
        for ad in suspicious:
            print(f"  [{ad.source}] {ad.title[:50]}", file=sys.stderr)
            print(f"    Display: {ad.displayed_url}", file=sys.stderr)
            print(f"    Actual:  {ad.actual_url[:60]}", file=sys.stderr)
            print(f"    Reasons: {ad.suspicion_reasons}", file=sys.stderr)
    
    print(f"\nWrote {len(results)} results to {args.out}", file=sys.stderr)
    
    # Run Evilginx detection on suspicious ads if requested
    if args.detect_evilginx and suspicious:
        print("\nRunning Evilginx detection on suspicious ads...", file=sys.stderr)
        for ad in suspicious:
            result = evilginx_mod.detect_evilginx(ad.actual_url, deep_check=True)
            if result.is_evilginx:
                print(f"  🚨 EVILGINX CONFIRMED: {ad.actual_url}", file=sys.stderr)
                print(f"     Confidence: {result.confidence}, Markers: {result.markers_found}", file=sys.stderr)


def cmd_signatures(args: argparse.Namespace) -> None:
    """Show signature database statistics."""
    stats = signatures.get_signature_stats()
    
    print("AiTM Hunter Signature Database")
    print("=" * 50)
    print(f"JA4 Client Fingerprints:    {stats['ja4_client']:4d}")
    print(f"JA4S Server Fingerprints:   {stats['ja4s_server']:4d}")
    print(f"JA4X Cert Fingerprints:     {stats['ja4x_cert']:4d}")
    print(f"JA4H HTTP Fingerprints:     {stats['ja4h_http']:4d}")
    print(f"JA3 Legacy Fingerprints:    {stats['ja3_legacy']:4d}")
    print("-" * 50)
    print(f"Total Fingerprints:         {stats['total_fingerprints']:4d}")
    print(f"Malware Families:           {stats['malware_families']:4d}")
    print("-" * 50)
    print(f"Known Evilginx Domains:     {stats['evilginx_domains']:4d}")
    print(f"Known Evilginx IPs:         {stats['evilginx_ips']:4d}")
    print(f"Suspicious ASNs:            {stats['suspicious_asns']:4d}")
    
    if args.list_domains:
        print("\nKnown Evilginx Domains:")
        for domain, info in signatures.KNOWN_EVILGINX_DOMAINS.items():
            status = info.get('status', 'unknown')
            target = info.get('target', 'unknown')
            print(f"  {domain:30s} [{status:8s}] -> {target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aitm_hunter")
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Run a search query and triage all results.")
    p_search.add_argument("--query", help="Search query, e.g. 'o365 login'")
    p_search.add_argument("--manual-input", help="Path to manually-collected results (JSON/CSV) instead of querying SerpApi")
    p_search.add_argument("--num-results", type=int, default=20)
    p_search.add_argument(
        "--brand",
        action="append",
        help=(
            "Brand to check typosquats against (key in triage.DEFAULT_BRAND_DOMAINS, "
            "e.g. 'microsoft'). Repeatable: --brand microsoft --brand okta. "
            "If omitted, all configured brands are checked."
        ),
    )
    p_search.add_argument("--out", required=True)
    p_search.set_defaults(func=cmd_search)

    p_fp = sub.add_parser(
        "fingerprint", 
        help="Run TLS/behavioral fingerprinting on triaged results (safe, no JS execution)."
    )
    p_fp.add_argument("--input", required=True, help="JSON output from the search/triage step")
    p_fp.add_argument("--out", required=True)
    p_fp.add_argument("--risk-threshold", type=int, default=30, 
                      help="Only fingerprint records with risk >= threshold (default: 30)")
    p_fp.add_argument("--skip-tls", action="store_true", 
                      help="Skip TLS certificate fingerprinting")
    p_fp.add_argument("--skip-proxy-check", action="store_true",
                      help="Skip live proxy behavior probing")
    p_fp.set_defaults(func=cmd_fingerprint)

    p_deep = sub.add_parser("deepcrawl", help="Deep-crawl high-risk survivors from a triage file. READ SAFETY.md FIRST.")
    p_deep.add_argument("--input", required=True, help="JSON output from the search/triage or fingerprint step")
    p_deep.add_argument("--out", required=True)
    p_deep.add_argument("--artifact-dir", default="results/artifacts")
    p_deep.add_argument("--risk-threshold", type=int, default=50)
    p_deep.add_argument(
        "--i-have-read-safety-md",
        action="store_true",
        help="Required. Confirms you're running this from an isolated, disposable host per SAFETY.md.",
    )
    p_deep.set_defaults(func=cmd_deepcrawl)

    p_report = sub.add_parser("report", help="Generate a CSV/JSON report from triaged/deep-crawled data.")
    p_report.add_argument("--input", required=True)
    p_report.add_argument("--out", required=True)
    p_report.add_argument("--risk-threshold", type=int, default=50)
    p_report.set_defaults(func=cmd_report)

    # Evilginx detection command
    p_evilginx = sub.add_parser(
        "evilginx",
        help="Run Evilginx-specific detection on URLs."
    )
    p_evilginx.add_argument("--url", help="Single URL to analyze")
    p_evilginx.add_argument("--input", help="JSON file with URLs to analyze")
    p_evilginx.add_argument("--out", required=True, help="Output JSON file")
    p_evilginx.add_argument("--quick", action="store_true",
                           help="Quick mode - URL pattern matching only, no network checks")
    p_evilginx.set_defaults(func=cmd_evilginx)

    # Malvertising detection command
    p_malvert = sub.add_parser(
        "malvertising",
        help="Search for malvertising in sponsored ads (requires Playwright for browser scraping)."
    )
    p_malvert.add_argument("--query", required=True, help="Search query to look for malvertising")
    p_malvert.add_argument("--out", required=True, help="Output JSON file")
    p_malvert.add_argument("--bing-api", action="store_true",
                          help="Also use Bing Ads API (requires BING_ADS_API_KEY or BING_SEARCH_API_KEY)")
    p_malvert.add_argument("--bing-api-key", help="Bing API key (or set BING_ADS_API_KEY env var)")
    p_malvert.add_argument("--visible", action="store_true",
                          help="Run browser in visible mode (not headless)")
    p_malvert.add_argument("--detect-evilginx", action="store_true",
                          help="Run Evilginx detection on suspicious ads")
    p_malvert.set_defaults(func=cmd_malvertising)

    # Signatures database command
    p_sigs = sub.add_parser(
        "signatures",
        help="Show signature database statistics."
    )
    p_sigs.add_argument("--list-domains", action="store_true",
                       help="List known Evilginx domains")
    p_sigs.set_defaults(func=cmd_signatures)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
