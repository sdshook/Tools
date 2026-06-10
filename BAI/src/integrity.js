// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// Browser Audit Inventory — integrity primitives
//
// Every artifact is hashed over the *exact bytes written to disk*. JSON is
// serialized once; those same bytes are both hashed and written. This is what
// makes the package re-verifiable later with a plain `sha256sum`.

/**
 * SHA-256 of the input, returned as lowercase hex.
 * @param {ArrayBuffer|Uint8Array|string} data
 * @returns {Promise<string>}
 */
export async function sha256Hex(data) {
  let bytes;
  if (typeof data === 'string') {
    bytes = new TextEncoder().encode(data);
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    bytes = new Uint8Array(data);
  }
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Serialize an object to canonical-ish pretty JSON and return both the bytes
 * to write and their hash. (Pretty-printed for human review; the hash is over
 * these exact bytes, so a verifier hashes the file as-is.)
 * @param {unknown} obj
 * @returns {Promise<{bytes: Uint8Array, sha256: string, text: string}>}
 */
export async function jsonArtifact(obj) {
  const text = JSON.stringify(obj, null, 2) + '\n';
  const bytes = new TextEncoder().encode(text);
  const sha256 = await sha256Hex(bytes);
  return { bytes, sha256, text };
}

/**
 * Deterministic root hash over the whole artifact set. We hash a sorted list
 * of "relative/path\tsha256" lines so the value is independent of write order
 * and reproducible by anyone holding the package.
 * @param {{path: string, sha256: string}[]} entries
 * @returns {Promise<string>}
 */
export async function rootHash(entries) {
  const lines = entries
    .map((e) => `${e.path}\t${e.sha256}`)
    .sort()
    .join('\n');
  return sha256Hex(lines + '\n');
}
