# Chrome Extension Signing

## Why This Package Is Not "Signed"

Chrome extensions can only be legitimately signed through two mechanisms:

### 1. Chrome Web Store (Public Distribution)
- Google reviews and signs the extension
- Users can install without Developer mode
- Requires a $5 Google Developer account
- Extension is publicly listed (or unlisted with direct link)

### 2. Enterprise Policy (Managed Devices)
- Organizations deploy `.crx` files via Group Policy
- Requires Chrome enterprise enrollment
- Not applicable to personal devices

## Self-Signed .crx Files

Prior to Chrome 75, you could pack an extension into a `.crx` file with your
own private key. However, Chrome now **blocks installation** of self-signed
`.crx` files for security reasons. This was done to prevent malware from
side-loading extensions.

Self-signed `.crx` files only work:
- In Developer mode (same as "Load unpacked")
- Via enterprise policy on managed devices
- In Chromium-based browsers with security checks disabled

## BAI Distribution Model

BAI is distributed as a `.zip` archive intended for "Load unpacked" installation
in Developer mode. This is appropriate because:

1. **Forensic Tool**: BAI is designed for security professionals conducting
   authorized assessments, not general consumers

2. **No Web Store**: Publishing forensic/security tools on the Chrome Web Store
   introduces review delays and potential policy conflicts

3. **Transparency**: The source code is visible and auditable when loaded
   unpacked, which is valuable for a forensic tool

4. **Integrity Verification**: The SHA-256 checksum allows verification that
   the package has not been tampered with

## Verifying Package Integrity

While BAI is not cryptographically signed by Google, you can verify its
integrity using the provided checksum:

```bash
sha256sum BAI_v0.4.0.zip
# Compare output to BAI_v0.4.0.zip.sha256
```

## Future Considerations

If Chrome Web Store distribution is desired:
1. Create a Google Developer account ($5 one-time fee)
2. Submit BAI for review
3. Once approved, users can install without Developer mode
4. Updates are automatically distributed

Contact the author for inquiries about Chrome Web Store publication.
