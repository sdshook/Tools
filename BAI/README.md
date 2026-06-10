# BAI: Browser Audit Inventory

> © 2026, Shane Shook, All Rights Reserved. This tool is for testing and analysis.

A local, operator-driven Chrome extension that captures artifacts from the
**currently signed-in Chrome profile**, hashes each one with SHA-256, and writes
a self-verifying evidence package to a folder you choose, including a USB drive.

Built for assessing **Adversary-in-the-Middle (AiTM) phishing attacks** and
**Infostealer malware techniques** by collecting browser history, settings, and
cookie data as forensic evidence.

Designed for personal, unmanaged Chromebooks. No Web Store, no enterprise policy,
no network activity.

---

## Browser Compatibility

| Browser | Status | Notes |
|---------|--------|-------|
| Chrome | ✅ Supported | Primary target, full functionality |
| Microsoft Edge | ✅ Supported | Chromium-based, works as-is |
| Brave | ✅ Supported | Chromium-based, works as-is |
| Opera | ✅ Supported | Chromium-based, works as-is |
| Firefox | 🔲 Planned | Requires porting (`browser.*` APIs, no File System Access) |
| Safari | 🔲 Planned | Requires separate build (Xcode, Apple Developer account) |

**Note:** BAI currently targets Chromium-based browsers which share the same
extension APIs. Firefox and Safari have fundamentally different extension
architectures and would require dedicated builds.

---

## What It Captures (v0.9.0)

### Core Browser Data (8 collectors)
| Artifact | Source API | Notes |
| --- | --- | --- |
| Browsing history | `chrome.history` | Windowed pagination to get the full history |
| Cookies | `chrome.cookies` | Includes HttpOnly; across all cookie stores |
| Download records | `chrome.downloads` | Metadata only, not the downloaded bytes |
| Open-tab snapshots | `chrome.pageCapture` | One MHTML file per capturable tab |
| Bookmarks | `chrome.bookmarks` | Full bookmark tree with folders |
| Installed extensions | `chrome.management` | All extensions and apps with permissions |
| Recently closed tabs | `chrome.sessions` | Session history of closed tabs and windows |
| Top sites | `chrome.topSites` | Most visited sites from new tab page |

### Security and Settings (4 collectors)
| Artifact | Source API | Notes |
| --- | --- | --- |
| Proxy settings | `chrome.proxy` | **Critical for AiTM detection** |
| Privacy settings | `chrome.privacy` | Safe browsing, tracking, cookie policies |
| Content settings | `chrome.contentSettings` | Site permissions (notifications, camera, etc.) |
| Search engines | `chrome.search` | Default search engine detection |

### Deep Collection via Content Script (10 collectors)
| Artifact | Source API | Notes |
| --- | --- | --- |
| Web storage | localStorage/sessionStorage | **Auth tokens, session data from open tabs** |
| IndexedDB structure | IndexedDB API | Database structure and record counts |
| IndexedDB full dump | IndexedDB API | **Actual database records** (limited to 100/store) |
| Service workers | navigator.serviceWorker | Registered workers (persistence mechanism) |
| Cache storage | Cache Storage API | Cached URLs per origin |
| Storage estimates | navigator.storage.estimate | Quota usage per origin |
| Performance timing | Performance API | **Redirects and timing (AiTM indicator)** |
| Visit details | `chrome.history.getVisits` | Per-URL visit history with transition types |
| WebAuthn/FIDO | PublicKeyCredential API | **Passkey and security key capabilities** |
| Media devices | navigator.mediaDevices | Cameras, microphones, permission states |

### System and Account (7 collectors)
| Artifact | Source API | Notes |
| --- | --- | --- |
| Chrome account | `chrome.identity` | **Signed-in Google account email** |
| System info | `chrome.system.*` | **CPU, memory, storage, platform details** |
| Extension permissions | `chrome.permissions` | Granted permissions |
| Window state | `chrome.windows` | Open windows and positions |
| Detailed tabs | `chrome.tabs` | Full tab state with audio, mute, grouping |
| Reading list | `chrome.readingList` | Saved articles (Chrome 120+) |
| Environment | Runtime APIs | Browser version, platform, timezone |

Each run also writes:
- `MANIFEST.json` - Every artifact with its hash, plus a root hash
- `MANIFEST.json.sha256` - Seal file for verification
- `chain_of_custody.json` - Event ledger for the acquisition workflow
- `session_log.json` - **Complete log of all events and errors during acquisition**
- `VERIFY.txt` - Re-verification steps

By default the whole package is written as a single sealed `.zip` (plus a
`.zip.sha256` of the archive). Untick "Package as a single .zip file" in step 3
to write a loose folder tree instead. The zip uses Chrome's built-in compression
and a self-contained writer. No third-party library is bundled.

## One-Click Verifier

BAI includes a built-in **Package Verifier** that lets you drop a `.zip` package
and get instant pass/fail verification. No manual `sha256sum` commands needed.
The verifier checks:

- Manifest seal (SHA-256 of MANIFEST.json)
- Root hash (computed from all artifacts)
- Each artifact's individual hash
- Digital signature (if present)

Access it via the "Open Package Verifier" link in the acquisition console footer,
or directly at `src/verify.html`.

## Signing (Optional)

The seal (`MANIFEST.json.sha256`) proves a package is unaltered. A *signature*
additionally proves *who* sealed it.

### Key Types

BAI supports two types of signing keys:

1. **Secure keys** (default): The private key is **non-extractable**. It cannot
   be exported or copied out, so it cannot be stolen from the package or profile.
   However, it also cannot be backed up or moved to another machine.

2. **Portable keys**: The private key is **exportable**. You can download it
   as a backup file and import it on another machine. This provides key continuity
   across devices but is less secure since the key file must be protected.

### Key Management

- **Generate secure key**: Creates a non-exportable key bound to this browser
- **Generate portable key**: Creates an exportable key that can be backed up
- **Import key**: Load a previously exported portable key
- **Backup private key**: Download the portable key for safekeeping (only for portable keys)
- **Download public key**: Get the public key to share with verifiers

When signing is enabled, each run writes `SIGNATURE.json`, a detached ECDSA
P-256/SHA-256 signature over the exact bytes of `MANIFEST.json`, together with
the public key and fingerprint. `MANIFEST.json` also records that it was signed
and by which key fingerprint. A valid signature proves the package was sealed by
the holder of that key. To attribute it to you specifically, the verifier compares
the fingerprint to your independently known public key.

## Install (Personal Chromebook)

1. Copy this folder somewhere **local** (e.g., your Downloads). Do not run it from
   the USB stick itself. If the stick is ejected, the extension breaks. The USB
   is for output only.
2. Go to `chrome://extensions`.
3. Turn on **Developer mode** (top-right). This is the per-browser extensions
   toggle, *not* ChromeOS device developer mode, which you do not need.
4. Click **Load unpacked** and select this folder.

> If "Load unpacked" is greyed out, the Chromebook is managed by an
> organization and an admin has disabled it. There is no workaround from the
> user side.

## Run an Acquisition

1. Click the toolbar icon. The console opens in a full tab (not a popup, so it
   survives losing focus while the file picker is open).
2. Fill in the case ID, examiner, and authorization basis, and tick the
   authorization box.
3. Choose which artifacts to collect.
4. Click **Select destination folder** and pick your USB drive (it appears under
   removable storage in the picker).
5. Click **Run acquisition**. Watch the live log. When it finishes, the seal
   panel shows the root hash and manifest seal. Record the seal hash.

## Verify a Package Later

Open `VERIFY.txt` inside the package, or in short: `sha256sum MANIFEST.json` must
equal `MANIFEST.json.sha256`; each file's hash must match its `artifacts` entry
in the manifest; and the root hash recomputes from the sorted `path<TAB>sha256`
lines.

## Known Limitations

- This is a **live acquisition of one signed-in profile**, not a forensic disk
  image. It is not bit-for-bit and the act of running it is part of profile state.
- It **cannot** reach saved passwords, autofill secrets, deleted records, other
  OS users' data, other Chrome profiles, or anything outside the browser.
- Timestamps come from this device's clock, **not** a trusted timestamp
  authority (RFC 3161).
- `chrome.pageCapture` captures only currently open tabs. Closed tabs are not
  snapshotted (their URLs still appear in history).
- Very large histories may truncate at a timestamp boundary. This is flagged in
  the manifest (`partial: true`).

## Not Yet Built (Roadmap)

### Browser Ports
- **Firefox version**: Port to Firefox WebExtensions (`browser.*` APIs),
  implement alternative to File System Access API using `downloads` API.
- **Safari version**: Native Safari Web Extension build requiring Xcode and
  Apple Developer account for distribution.

### Additional Collectors
- **Autofill data**: Chrome does not expose autofill to extensions (security restriction).
- **Geolocation**: Requires user gesture; not suitable for silent collection.
- **Clipboard contents**: Requires user gesture; not suitable for silent collection.
- **WebAuthn credential enumeration**: Cannot enumerate actual credentials (security).

### Features
- A normalized **timeline** view across artifacts and a human-readable report.
- **Trusted timestamps**: RFC 3161 timestamp authority integration.
- **Anomaly detection**: Flag suspicious patterns (unexpected redirects, proxy configs).
- **Differential analysis**: Compare two packages to identify changes.

## License

© 2026 Shane Shook. All Rights Reserved. This tool is for testing and analysis.
See the `LICENSE` file for full terms.
