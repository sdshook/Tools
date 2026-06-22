# Safety model

You already learned the hard lesson here: clicking a top-result AiTM link from
your normal browser cost you a token. This document is about not repeating
that with the automated version.

## Rule 1: deep-crawl only from a disposable, network-isolated environment

The `deepcrawl` stage launches a real, JS-executing browser and visits the
URL. That is exactly the action that phishes people. Treat every URL that
reaches this stage as hostile.

Recommended setup:

- A VM or container with **no SSO state, no saved credentials, no browser
  profile reused for anything else**, snapshotted so you can roll back after
  every run (or just destroy/recreate the container).
- Route its egress through a network path you're comfortable burning — a
  segment that isn't your corporate IP space, doesn't share a NAT gateway with
  anything sensitive, and ideally isn't attributable to your employer (some
  kits geofence/IP-fingerprint based on who's looking).
- No extensions, no password manager, no autofill.
- Disable any "open last session" / cookie persistence between runs.

If you don't have a sandboxed host available, **don't run `deepcrawl` at
all** — stop at the `triage` stage, which never executes JS or renders the
page, and hand off the surviving candidates to a security vendor or your
SOC's malware-analysis sandbox instead.

## Rule 2: never enter or transmit real or fake credentials

`deepcrawl.py` is deliberately built to never fill in form fields. It only
observes: it screenshots, captures the DOM, and logs the network (HAR). If
you extend it, do not add an "auto-fill test creds" feature — AiTM kits
proxy whatever you type straight to the real IdP, so even "fake" creds can
trigger real account lockouts, real MFA prompts to a real victim if you
guess a real username, or worse, real token theft if you reuse anything.

## Rule 3: treat every artifact you collect as live malware-adjacent content

Screenshots and HARs may contain the kit's JS, which can include further
redirect/exploitation logic. Store them in a contained location, don't open
captured HTML in a regular browser, and follow your org's malware-handling
procedures for storage/sharing (e.g. password-protected zips, access-controlled
share, not casually emailed around).

## Rule 4: respect scope and law

- Only crawl URLs you encountered through your own legitimate search activity
  or that were provided to you as part of an authorized investigation.
- Sending abuse reports (Google Ads, Microsoft DCU, Cloudflare, registrars) is
  fine and encouraged — that's the intended output of this tool.
- Don't use this tooling to interact with infrastructure in a way that could
  be construed as unauthorized access (e.g. trying to log into the kit's
  admin panel, brute-forcing paths, etc.). Passive observation only.

## Rule 5: rate limit yourself

Aggressive automated traffic against Google's SERPs (if you scrape directly
instead of using a SERP API) will get your IP blocked and may draw attention
in ways that aren't useful to you. Prefer a paid SERP API. If you must scrape
directly, keep volume low and human-paced.
