// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// Browser Audit Inventory — acquisition console controller
//
// Everything runs in this page (a real tab, not a popup) so the File System
// Access picker has a window context and a user gesture, and so a long
// acquisition is not killed by an ephemeral service worker.
//
// All artifacts are collected and hashed in memory, then written either as a
// single sealed .zip (default) or as a folder tree. The manifest and its
// SHA-256 seal are identical in both cases; only the container differs.

import {
  collectHistory, collectCookies, collectDownloads,
  collectTabSnapshots, collectBookmarks, collectExtensions,
  collectSessions, collectTopSites, collectProxySettings,
  collectPrivacySettings, collectContentSettings, collectSearchEngines,
  collectVisitDetails, collectWebStorage, collectIndexedDBInfo,
  collectServiceWorkers, collectCacheStorage, collectStorageEstimates,
  collectPerformanceTiming, collectPermissions, collectWindows,
  collectTabsDetailed, collectWebAuthnInfo, collectMediaDevicesInfo,
  collectIndexedDBFull, collectIdentity, collectSystemInfo,
  collectReadingList, collectEnvironment,
} from './collectors.js';
import { sha256Hex, jsonArtifact, rootHash } from './integrity.js';
import { buildZip } from './zip.js';
import * as signing from './signing.js';

const $ = (id) => document.getElementById(id);
const enc = (s) => new TextEncoder().encode(s);
const MANIFEST_SCHEMA = 'bai-manifest/1';
const COPYRIGHT = '© 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.';

let destHandle = null;
let running = false;
let keyRecord = null;

// ---- setup -----------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  $('version').textContent = 'v' + chrome.runtime.getManifest().version;

  if (typeof window.showDirectoryPicker !== 'function') {
    $('unsupported').classList.add('show');
    $('pickDest').disabled = true;
  }

  $('pickDest').addEventListener('click', pickDestination);
  $('run').addEventListener('click', runAcquisition);
  $('affirm').addEventListener('change', refreshRunState);
  document.querySelectorAll('.ev').forEach((c) => c.addEventListener('change', refreshRunState));
  $('copySeal').addEventListener('click', () => navigator.clipboard?.writeText($('rManifest').textContent || ''));
  $('copyContainer').addEventListener('click', () => navigator.clipboard?.writeText($('rContainer').textContent || ''));

  $('genKey').addEventListener('click', () => onGenerateKey(false));
  $('genKeyPortable').addEventListener('click', () => onGenerateKey(true));
  $('importKey').addEventListener('click', () => $('importKeyFile').click());
  $('importKeyFile').addEventListener('change', onImportKey);
  $('replaceKey').addEventListener('click', onReplaceKey);
  $('downloadPub').addEventListener('click', onDownloadPublicKey);
  $('downloadPriv').addEventListener('click', onDownloadPrivateKey);

  initSigning();
  refreshRunState();
});

async function initSigning() {
  try {
    keyRecord = await signing.loadKey();
  } catch {
    keyRecord = null;
  }
  refreshSigningUI();
}

function refreshSigningUI() {
  const has = Boolean(keyRecord);
  const isPortable = has && keyRecord.exportable;
  
  // Show generation row or management row
  $('keyGenRow').style.display = has ? 'none' : '';
  $('keyMgmtRow').style.display = has ? '' : 'none';
  
  // Show backup button only for portable keys
  $('downloadPriv').style.display = isPortable ? '' : 'none';
  
  $('signToggle').disabled = !has;
  if (!has) $('signToggle').checked = false;
  
  if (has) {
    const keyType = isPortable ? 'portable' : 'secure';
    $('keyStatus').textContent = `Key ready (${keyType}): fingerprint ${keyRecord.fingerprint}`;
    $('keyStatus').classList.add('set');
  } else {
    $('keyStatus').textContent = 'No signing key on this device. Generate or import one to sign packages.';
    $('keyStatus').classList.remove('set');
  }
}

async function onGenerateKey(exportable = false) {
  const keyType = exportable ? 'portable' : 'secure';
  $('keyStatus').textContent = `Generating ${keyType} key…`;
  try {
    keyRecord = await signing.generateKey(exportable);
    $('signToggle').checked = true;
  } catch (e) {
    $('keyStatus').textContent = `Could not generate key: ${e?.message || e}`;
    return;
  }
  refreshSigningUI();
}

async function onImportKey(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  
  $('keyStatus').textContent = 'Importing key…';
  try {
    const content = await file.text();
    keyRecord = await signing.importKey(content);
    $('signToggle').checked = true;
    refreshSigningUI();
  } catch (e) {
    $('keyStatus').textContent = `Could not import key: ${e?.message || e}`;
  }
  // Reset the file input so the same file can be selected again
  event.target.value = '';
}

async function onReplaceKey() {
  const isPortable = keyRecord?.exportable;
  let msg = 'Replace the signing key?\n\n';
  if (isPortable) {
    msg += 'The current key is portable. If you have not backed it up, you will lose access to it.\n\n';
  } else {
    msg += 'The current key is secure (non-exportable) and cannot be recovered.\n\n';
  }
  msg += 'Packages already signed with it will no longer match the new public key. Continue?';
  
  const ok = confirm(msg);
  if (!ok) return;
  
  // Ask which type of new key they want
  const wantPortable = confirm('Generate a portable key?\n\nClick OK for portable (can backup), Cancel for secure (cannot export).');
  await onGenerateKey(wantPortable);
}

function onDownloadPublicKey() {
  if (!keyRecord) return;
  const blob = new Blob([signing.publicKeyFile(keyRecord)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `BAI_public_key_${keyRecord.fingerprint.slice(0, 12)}.jwk.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function onDownloadPrivateKey() {
  if (!keyRecord || !keyRecord.exportable) return;
  const content = signing.exportPrivateKeyFile(keyRecord);
  if (!content) {
    alert('This key is not exportable.');
    return;
  }
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `BAI_keypair_${keyRecord.fingerprint.slice(0, 12)}_PRIVATE.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function pickDestination() {
  try {
    destHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
    $('destName').textContent = `Selected: ${destHandle.name}`;
    $('destName').classList.add('set');
  } catch (err) {
    if (err?.name !== 'AbortError') $('destName').textContent = `Could not select folder: ${err?.message || err}`;
  }
  refreshRunState();
}

const selectedTypes = () => [...document.querySelectorAll('.ev:checked')].map((c) => c.value);

function refreshRunState() {
  const ready = !running && destHandle && $('affirm').checked && selectedTypes().length > 0;
  $('run').disabled = !ready;
  if (running) return;
  if (!$('affirm').checked) $('runState').textContent = 'Confirm authorization in step 1.';
  else if (!destHandle) $('runState').textContent = 'Select a destination folder in step 3.';
  else if (selectedTypes().length === 0) $('runState').textContent = 'Select at least one evidence type.';
  else $('runState').textContent = 'Ready.';
}

// ---- logging ---------------------------------------------------------------

// Session log captures all events for forensic record
const sessionLog = [];

function log(msg, cls = '') {
  const ts = new Date().toISOString();
  
  // Capture to session log
  sessionLog.push({
    timestamp: ts,
    level: cls || 'info',
    message: msg,
  });
  
  // Display in UI
  const line = document.createElement('div');
  const t = document.createElement('span');
  t.className = 't';
  t.textContent = ts + '  ';
  line.appendChild(t);
  const body = document.createElement('span');
  if (cls) body.className = cls;
  body.textContent = msg;
  line.appendChild(body);
  $('log').appendChild(line);
  $('log').scrollTop = $('log').scrollHeight;
}

function clearSessionLog() {
  sessionLog.length = 0;
}

function getSessionLog() {
  return [...sessionLog];
}

// ---- filesystem helpers ----------------------------------------------------

async function writeFile(dir, name, data) {
  const fh = await dir.getFileHandle(name, { create: true });
  const w = await fh.createWritable();
  await w.write(data);
  await w.close();
}

async function writePath(rootDir, path, bytes) {
  const parts = path.split('/');
  let dir = rootDir;
  for (let i = 0; i < parts.length - 1; i++) dir = await dir.getDirectoryHandle(parts[i], { create: true });
  await writeFile(dir, parts[parts.length - 1], bytes);
}

const safe = (s, fallback) =>
  (s || '').trim().replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || fallback;

function hostOf(url) {
  try { return new URL(url).hostname || 'page'; } catch { return 'page'; }
}

// ---- acquisition -----------------------------------------------------------

async function runAcquisition() {
  running = true;
  $('run').disabled = true;
  $('pickDest').disabled = true;
  $('seal').classList.remove('show');
  $('log').textContent = '';
  $('runState').textContent = 'Running…';

  // Clear session log from any previous run
  clearSessionLog();

  const startedUtc = new Date().toISOString();
  const collectionId = crypto.randomUUID();
  const zipMode = $('zipMode').checked;
  const ledger = [];
  const record = (action, detail) =>
    ledger.push({ timestamp_utc: new Date().toISOString(), operator: $('examiner').value.trim() || 'unspecified', action, detail });

  const meta = {
    case_id: $('caseId').value.trim() || 'unspecified',
    examiner: $('examiner').value.trim() || 'unspecified',
    authority_reference: $('authority').value.trim() || 'unspecified',
    notes: $('notes').value.trim() || '',
  };
  const env = collectEnvironment();
  const types = selectedTypes();

  log(`collection ${collectionId} started (${zipMode ? 'zip' : 'folder'})`, 'ok');
  record('session_started', { collection_id: collectionId, scope: types, container: zipMode ? 'zip' : 'folder' });

  const outputs = [];    // { path, bytes } — every file in the package
  const artifacts = [];  // manifest entries (evidence + chain), not manifest/seal/verify

  const addArtifact = async (path, bytes, m) => {
    const sha256 = await sha256Hex(bytes);
    outputs.push({ path, bytes });
    artifacts.push({ path, ...m, byte_size: bytes.byteLength, sha256 });
    return sha256;
  };

  try {
    const folderName = `BAI_${safe(meta.case_id, 'case')}_${startedUtc.replace(/[:.]/g, '-')}`;

    // --- JSON artifacts ---
    const jsonJobs = {
      history: collectHistory,
      cookies: collectCookies,
      downloads: collectDownloads,
      bookmarks: collectBookmarks,
      extensions: collectExtensions,
      sessions: collectSessions,
      topsites: collectTopSites,
      proxy: collectProxySettings,
      privacy: collectPrivacySettings,
      contentsettings: collectContentSettings,
      searchengines: collectSearchEngines,
      visitdetails: collectVisitDetails,
      webstorage: collectWebStorage,
      indexeddb: collectIndexedDBInfo,
      serviceworkers: collectServiceWorkers,
      cachestorage: collectCacheStorage,
      storageestimates: collectStorageEstimates,
      performance: collectPerformanceTiming,
      permissions: collectPermissions,
      windows: collectWindows,
      tabsdetailed: collectTabsDetailed,
      webauthn: collectWebAuthnInfo,
      mediadevices: collectMediaDevicesInfo,
      indexeddbfull: collectIndexedDBFull,
      identity: collectIdentity,
      systeminfo: collectSystemInfo,
      readinglist: collectReadingList,
    };
    for (const [type, fn] of Object.entries(jsonJobs)) {
      if (!types.includes(type)) continue;
      try {
        const data = await fn((mm) => log(mm));
        const { bytes } = await jsonArtifact(data);
        const sha = await addArtifact(`${type}.json`, bytes, {
          artifact_type: data.artifact_type, source_api: data.source_api,
          record_count: data.record_count, partial: Boolean(data.truncated),
          notes: data.truncated ? 'history may be truncated at a timestamp boundary' : '',
        });
        log(`collected ${type}.json — ${data.record_count} records — ${sha.slice(0, 16)}…`, 'ok');
        record('artifact_collected', { path: `${type}.json`, record_count: data.record_count, sha256: sha });
      } catch (err) {
        log(`FAILED ${type}: ${err?.message || err}`, 'err');
        record('artifact_failed', { type, error: String(err?.message || err) });
        artifacts.push({ path: `${type}.json`, artifact_type: type, source_api: '', record_count: 0, byte_size: 0, sha256: '', partial: true, notes: `collection failed: ${err?.message || err}` });
      }
    }

    // --- tab snapshots (MHTML) ---
    if (types.includes('snapshots')) {
      try {
        const snap = await collectTabSnapshots((mm) => log(mm));
        const index = [];
        let n = 0;
        for (const s of snap.snapshots) {
          const entry = { tab_index: s.index, url: s.url, title: s.title, captured: s.captured, reason: s.reason, file: null, sha256: null, byte_size: 0 };
          if (s.captured && s.bytes) {
            const fname = `snapshots/snapshot_${String(n).padStart(3, '0')}_${safe(hostOf(s.url), 'page')}.mhtml`;
            const sha = await addArtifact(fname, s.bytes, { artifact_type: 'tab_snapshot', source_api: snap.source_api, record_count: 1, partial: false, notes: s.url });
            entry.file = fname; entry.sha256 = sha; entry.byte_size = s.bytes.byteLength;
            log(`collected ${fname} — ${sha.slice(0, 16)}…`, 'ok');
            n++;
          }
          index.push(entry);
        }
        const { bytes } = await jsonArtifact({
          artifact_type: 'tab_snapshots_index', source_api: snap.source_api,
          record_count: snap.record_count, captured_count: snap.captured_count, snapshots: index,
        });
        await addArtifact('snapshots_index.json', bytes, {
          artifact_type: 'tab_snapshots_index', source_api: snap.source_api,
          record_count: snap.record_count, partial: snap.captured_count < snap.record_count,
          notes: `${snap.captured_count}/${snap.record_count} tabs captured`,
        });
        log(`collected snapshots_index.json — ${snap.captured_count}/${snap.record_count} captured`, 'ok');
        record('artifact_collected', { path: 'snapshots_index.json', captured: snap.captured_count, total: snap.record_count });
      } catch (err) {
        log(`FAILED snapshots: ${err?.message || err}`, 'err');
        record('artifact_failed', { type: 'snapshots', error: String(err?.message || err) });
      }
    }

    // --- chain of custody (added before manifest so it is covered by the root hash) ---
    record('collection_complete', { artifact_count: artifacts.length });
    const collectionCompletedUtc = new Date().toISOString();
    const ledgerArt = await jsonArtifact({
      schema: 'bai-chain-of-custody/1', collection_id: collectionId,
      workflow: 'Collection -> Package -> Review -> Archive', events: ledger,
    });
    await addArtifact('chain_of_custody.json', ledgerArt.bytes, { artifact_type: 'chain_of_custody', source_api: 'local', record_count: ledger.length, partial: false, notes: '' });
    log(`collected chain_of_custody.json: ${ledger.length} events`, 'ok');

    // --- session log (all events and errors from this run) ---
    const sessionLogData = getSessionLog();
    const sessionLogArt = await jsonArtifact({
      schema: 'bai-session-log/1',
      collection_id: collectionId,
      started_utc: startedUtc,
      completed_utc: collectionCompletedUtc,
      entry_count: sessionLogData.length,
      error_count: sessionLogData.filter(e => e.level === 'err').length,
      warning_count: sessionLogData.filter(e => e.level === 'warn').length,
      entries: sessionLogData,
    });
    await addArtifact('session_log.json', sessionLogArt.bytes, { artifact_type: 'session_log', source_api: 'local', record_count: sessionLogData.length, partial: false, notes: 'Complete log of all acquisition events and errors' });
    log(`collected session_log.json: ${sessionLogData.length} entries, ${sessionLogData.filter(e => e.level === 'err').length} errors`, 'ok');

    // --- root hash, then manifest ---
    const root = await rootHash(artifacts.map((a) => ({ path: a.path, sha256: a.sha256 || 'MISSING' })));
    const packagedUtc = new Date().toISOString();

    const signingIntent = Boolean(keyRecord) && $('signToggle').checked;
    const buildManifest = (signingBlock) => ({
      schema_version: MANIFEST_SCHEMA,
      collection_id: collectionId,
      packaging: { container: zipMode ? 'zip' : 'folder', container_root: folderName },
      tool: { name: env.extension_name, version: env.extension_version, extension_id: env.extension_id, copyright: COPYRIGHT },
      case: meta,
      authorization: { confirmed: true, confirmed_at_utc: startedUtc },
      signing: signingBlock,
      environment: { ...env, clock_source: 'local device clock (not a trusted timestamp authority)' },
      acquisition: { started_utc: startedUtc, collection_completed_utc: collectionCompletedUtc, packaged_utc: packagedUtc, scope: types },
      artifacts,
      totals: {
        artifact_count: artifacts.length,
        total_bytes: artifacts.reduce((s, a) => s + (a.byte_size || 0), 0),
        partial_artifacts: artifacts.filter((a) => a.partial).length,
      },
      root_hash: { algorithm: 'SHA-256', value: root, definition: "SHA-256 over sorted 'path<TAB>sha256' lines, newline-joined, with a trailing newline" },
    });

    let manifestObj = buildManifest(
      signingIntent
        ? { signed: true, algorithm: signing.SIGNATURE_ALGORITHM, signature_format: signing.SIGNATURE_FORMAT, public_key_fingerprint_sha256: keyRecord.fingerprint, signer_label: meta.examiner, signature_file: 'SIGNATURE.json' }
        : { signed: false },
    );
    let manifestArt = await jsonArtifact(manifestObj);

    let signatureFile = null;
    if (signingIntent) {
      try {
        const sigB64 = await signing.sign(keyRecord, manifestArt.bytes);
        const sigDoc = {
          schema: 'bai-signature/1',
          signed_file: 'MANIFEST.json',
          algorithm: signing.SIGNATURE_ALGORITHM,
          signature_format: signing.SIGNATURE_FORMAT,
          signature: sigB64,
          signer: { label: meta.examiner, public_key_fingerprint_sha256: keyRecord.fingerprint },
          public_key_jwk: keyRecord.publicJwk,
          signed_at_utc: new Date().toISOString(),
        };
        signatureFile = { path: 'SIGNATURE.json', bytes: enc(JSON.stringify(sigDoc, null, 2) + '\n') };
        log(`signed MANIFEST.json with key ${keyRecord.fingerprint.slice(0, 16)}…`, 'ok');
        record('manifest_signed', { fingerprint: keyRecord.fingerprint });
      } catch (err) {
        log(`signing failed: ${err?.message || err} — writing unsigned package`, 'err');
        record('signing_failed', { error: String(err?.message || err) });
        manifestObj = buildManifest({ signed: false, error: String(err?.message || err) });
        manifestArt = await jsonArtifact(manifestObj);
      }
    }
    const signed = Boolean(signatureFile);

    // package files = artifacts + manifest + seal + verifier notes (+ signature)
    const pkgFiles = [
      ...outputs,
      { path: 'MANIFEST.json', bytes: manifestArt.bytes },
      { path: 'MANIFEST.json.sha256', bytes: enc(`${manifestArt.sha256}  MANIFEST.json\n`) },
      { path: 'VERIFY.txt', bytes: enc(verifyText(manifestArt.sha256, root, zipMode, folderName, signed, keyRecord?.fingerprint)) },
    ];
    if (signatureFile) pkgFiles.push(signatureFile);

    // --- persist ---
    let containerName = null, containerHash = null, destLabel;
    if (zipMode) {
      const zipBytes = await buildZip(pkgFiles.map((f) => ({ name: `${folderName}/${f.path}`, data: f.bytes })), new Date(startedUtc));
      containerName = `${folderName}.zip`;
      await writeFile(destHandle, containerName, zipBytes);
      containerHash = await sha256Hex(zipBytes);
      await writeFile(destHandle, `${containerName}.sha256`, enc(`${containerHash}  ${containerName}\n`));
      destLabel = `${destHandle.name}/${containerName}`;
      log(`wrote ${containerName} (${zipBytes.length.toLocaleString()} bytes) — ${containerHash}`, 'ok');
    } else {
      const caseDir = await destHandle.getDirectoryHandle(folderName, { create: true });
      for (const f of pkgFiles) await writePath(caseDir, f.path, f.bytes);
      destLabel = `${destHandle.name}/${folderName}`;
      log(`wrote ${pkgFiles.length} files to ${folderName}/`, 'ok');
    }

    log(`MANIFEST.json sealed — ${manifestArt.sha256}`, 'ok');
    log('acquisition complete', 'ok');

    showSeal({ collectionId, destLabel, started: startedUtc, completed: packagedUtc, root, manifestHash: manifestArt.sha256, containerName, containerHash, artifacts, signed, fingerprint: keyRecord?.fingerprint });
    $('runState').textContent = zipMode ? 'Done. Package zipped and sealed.' : 'Done. Package written and sealed.';
  } catch (err) {
    log(`ACQUISITION ABORTED: ${err?.message || err}`, 'err');
    $('runState').textContent = `Aborted: ${err?.message || err}`;
  } finally {
    running = false;
    $('pickDest').disabled = typeof window.showDirectoryPicker !== 'function';
    refreshRunState();
  }
}

function showSeal(r) {
  $('rCollectionId').textContent = r.collectionId;
  $('rFolder').textContent = r.destLabel;
  $('rStarted').textContent = r.started;
  $('rCompleted').textContent = r.completed;
  $('rRoot').textContent = r.root;
  $('rManifest').textContent = r.manifestHash;
  $('rSignature').textContent = r.signed ? `ECDSA P-256, key ${r.fingerprint}` : 'not signed';

  if (r.containerHash) {
    $('rContainer').textContent = r.containerHash;
    $('containerBox').style.display = '';
  } else {
    $('containerBox').style.display = 'none';
  }

  const tb = $('rFiles');
  tb.textContent = '';
  for (const a of r.artifacts) {
    const tr = document.createElement('tr');
    const cells = [a.path, a.artifact_type, String(a.record_count ?? ''), String(a.byte_size ?? ''), a.sha256 || '—'];
    cells.forEach((v, i) => {
      const td = document.createElement('td');
      td.textContent = v;
      if (i === 4) td.className = 'h';
      if (a.partial && i === 0) td.className = 'partial';
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  }
  $('seal').classList.add('show');
}

function verifyText(manifestHash, root, zipMode, folderName, signed, fingerprint) {
  const lines = [
    'BAI — package verification',
    '==========================',
    '',
  ];
  if (zipMode) {
    lines.push(
      'This package is a single .zip. A SHA-256 of the archive is written beside',
      `it as ${folderName}.zip.sha256 — confirm that first:`,
      `     sha256sum ${folderName}.zip`,
      'Then extract the archive and run the checks below from inside the folder.',
      '',
    );
  }
  lines.push(
    'To verify on any machine with standard tools (Linux/macOS shown; use',
    'certutil on Windows):',
    '',
    '1. Confirm the manifest seal:',
    '     sha256sum MANIFEST.json',
    '   It must equal the value in MANIFEST.json.sha256:',
    `     ${manifestHash}  MANIFEST.json`,
    '',
    '2. Confirm each artifact:',
    '   For every entry in MANIFEST.json "artifacts", hash the file at its "path"',
    '   and compare to its "sha256".',
    '',
    '3. Recompute the root hash:',
    '   For each artifact, form the line  <path><TAB><sha256>',
    '   sort the lines, join with newlines, add a trailing newline, and SHA-256 it.',
    '   It must equal MANIFEST.json "root_hash.value":',
    `     ${root}`,
    '',
  );
  if (signed) {
    lines.push(
      '4. Verify the signature (authenticity):',
      '   SIGNATURE.json holds an ECDSA P-256 / SHA-256 signature over the exact',
      '   bytes of MANIFEST.json, plus the signer\'s public key (JWK).',
      '   The signature is raw IEEE-P1363 (r||s), base64. Verify with Web Crypto:',
      '     key = await crypto.subtle.importKey("jwk", <public_key_jwk>,',
      '             {name:"ECDSA",namedCurve:"P-256"}, true, ["verify"]);',
      '     ok  = await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"}, key,',
      '             <base64-decoded signature>, <bytes of MANIFEST.json>);',
      '   The public key fingerprint (SHA-256 of its raw point) is:',
      `     ${fingerprint}`,
      '   A valid signature proves the package was sealed by the holder of that',
      '   key. To attribute it to a specific operator, compare the fingerprint to',
      '   that operator\'s independently known public key.',
      '   (openssl users: convert the P1363 signature to DER first.)',
      '',
    );
  }
  lines.push(
    'Timestamps are from the acquiring device clock, not a trusted timestamp',
    'authority. This is a live acquisition of a single signed-in Chrome profile.',
    '',
  );
  return lines.join('\n');
}
