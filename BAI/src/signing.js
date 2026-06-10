// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// BAI — operator signing key + manifest signing.
//
// The manifest seal (a SHA-256) proves a package was not altered. A signature
// additionally proves it was sealed by the holder of a specific private key —
// i.e. who sealed it. We use ECDSA P-256 with SHA-256.
//
// Two key modes are supported:
// 1. NON-EXTRACTABLE (default): The private key cannot be exported or copied
//    out of this browser profile. More secure but cannot be backed up or moved.
// 2. EXPORTABLE (portable): The private key can be exported as JWK for backup
//    or transfer to another machine. Less secure but provides key continuity.
//
// The public key (and its fingerprint) is always exportable and travels in
// the package so anyone can verify.

import { sha256Hex } from './integrity.js';

const DB_NAME = 'bai';
const DB_VERSION = 2; // Upgraded for exportable key support
const STORE = 'keys';
const KEY_ID = 'operator-signing-key';

const GEN_ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' };

export const SIGNATURE_ALGORITHM = 'ECDSA-P256-SHA256';
export const SIGNATURE_FORMAT = 'IEEE-P1363 (raw r||s), base64';

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(id) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const r = db.transaction(STORE, 'readonly').objectStore(STORE).get(id);
    r.onsuccess = () => resolve(r.result ?? null);
    r.onerror = () => reject(r.error);
  });
}

async function idbPut(id, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, 'readwrite');
    t.objectStore(STORE).put(value, id);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

function toBase64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

async function fingerprintOf(publicKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', publicKey));
  return sha256Hex(raw);
}

/** Load the stored signing key record, or null. */
export async function loadKey() {
  return idbGet(KEY_ID);
}

/**
 * Generate a fresh signing key, persist it, and return its record.
 * @param {boolean} exportable - If true, the private key can be exported (portable mode)
 */
export async function generateKey(exportable = false) {
  const pair = await crypto.subtle.generateKey(GEN_ALG, exportable, ['sign', 'verify']);
  // For an EC key pair the public key is always extractable even though the
  // private key may not be, so we can publish the public key and fingerprint.
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const fingerprint = await fingerprintOf(pair.publicKey);
  
  // For exportable keys, also store the private JWK for backup/transfer
  let privateJwk = null;
  if (exportable) {
    privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  }
  
  const record = {
    privateKey: pair.privateKey, // CryptoKey, structured-cloned into IndexedDB
    publicJwk,
    privateJwk, // null if non-extractable, JWK if exportable
    fingerprint,
    exportable,
    created_utc: new Date().toISOString(),
  };
  await idbPut(KEY_ID, record);
  return record;
}

/**
 * Export the private key as a downloadable JSON file (only works for exportable keys).
 * @param {object} record - Key record from loadKey/generateKey
 * @returns {string|null} - JSON string for download, or null if key is not exportable
 */
export function exportPrivateKeyFile(record) {
  if (!record.exportable || !record.privateJwk) {
    return null;
  }
  return JSON.stringify({
    schema: 'bai-keypair/1',
    warning: 'This file contains your BAI signing private key. Keep it secure and never share it.',
    algorithm: SIGNATURE_ALGORITHM,
    fingerprint_sha256: record.fingerprint,
    created_utc: record.created_utc,
    exportable: true,
    public_key_jwk: record.publicJwk,
    private_key_jwk: record.privateJwk,
  }, null, 2) + '\n';
}

/**
 * Import a previously exported key pair from JSON.
 * @param {string} jsonContent - The JSON content of an exported key file
 * @returns {Promise<object>} - The imported key record
 */
export async function importKey(jsonContent) {
  const data = JSON.parse(jsonContent);
  
  if (data.schema !== 'bai-keypair/1') {
    throw new Error('Invalid key file format');
  }
  if (!data.private_key_jwk || !data.public_key_jwk) {
    throw new Error('Key file missing required key data');
  }
  
  // Import the private key as an extractable CryptoKey
  const privateKey = await crypto.subtle.importKey(
    'jwk', data.private_key_jwk, GEN_ALG, true, ['sign']
  );
  
  // Import the public key to verify and get fingerprint
  const publicKey = await crypto.subtle.importKey(
    'jwk', data.public_key_jwk, GEN_ALG, true, ['verify']
  );
  
  // Verify the fingerprint matches
  const fingerprint = await fingerprintOf(publicKey);
  if (fingerprint !== data.fingerprint_sha256) {
    throw new Error('Key fingerprint mismatch - file may be corrupted');
  }
  
  const record = {
    privateKey,
    publicJwk: data.public_key_jwk,
    privateJwk: data.private_key_jwk,
    fingerprint,
    exportable: true,
    created_utc: data.created_utc,
    imported_utc: new Date().toISOString(),
  };
  
  await idbPut(KEY_ID, record);
  return record;
}

/**
 * Detached signature over the given bytes.
 * @param {object} record a key record from loadKey/generateKey
 * @param {Uint8Array} bytes
 * @returns {Promise<string>} base64 signature (raw P1363)
 */
export async function sign(record, bytes) {
  const sig = await crypto.subtle.sign(SIGN_ALG, record.privateKey, bytes);
  return toBase64(new Uint8Array(sig));
}

/** Public-key JWK as a downloadable, pretty-printed blob payload. */
export function publicKeyFile(record) {
  return JSON.stringify(
    { algorithm: SIGNATURE_ALGORITHM, fingerprint_sha256: record.fingerprint, created_utc: record.created_utc, public_key_jwk: record.publicJwk },
    null, 2,
  ) + '\n';
}
