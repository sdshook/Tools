// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// BAI — package verifier
//
// One-click verification of BAI evidence packages. Accepts a .zip file,
// extracts it in memory, verifies the manifest seal, recomputes the root hash,
// checks each artifact's hash, and optionally verifies the signature.

import { sha256Hex, rootHash } from './integrity.js';

const $ = (id) => document.getElementById(id);

// Simple ZIP reader (no external dependencies)
async function readZip(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const files = new Map();
  
  // Find end of central directory
  let eocdOffset = arrayBuffer.byteLength - 22;
  while (eocdOffset >= 0) {
    if (view.getUint32(eocdOffset, true) === 0x06054b50) break;
    eocdOffset--;
  }
  if (eocdOffset < 0) throw new Error('Invalid ZIP: EOCD not found');
  
  const cdOffset = view.getUint32(eocdOffset + 16, true);
  const cdCount = view.getUint16(eocdOffset + 10, true);
  
  let offset = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (view.getUint32(offset, true) !== 0x02014b50) throw new Error('Invalid ZIP: bad central directory');
    
    const method = view.getUint16(offset + 10, true);
    const compSize = view.getUint32(offset + 20, true);
    const uncompSize = view.getUint32(offset + 24, true);
    const nameLen = view.getUint16(offset + 28, true);
    const extraLen = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);
    const localOffset = view.getUint32(offset + 42, true);
    
    const nameBytes = new Uint8Array(arrayBuffer, offset + 46, nameLen);
    const name = new TextDecoder().decode(nameBytes);
    
    // Read local file header to get actual data offset
    const localNameLen = view.getUint16(localOffset + 26, true);
    const localExtraLen = view.getUint16(localOffset + 28, true);
    const dataOffset = localOffset + 30 + localNameLen + localExtraLen;
    
    if (!name.endsWith('/')) {
      let data;
      if (method === 0) {
        // Stored (uncompressed)
        data = new Uint8Array(arrayBuffer, dataOffset, uncompSize);
      } else if (method === 8) {
        // Deflate
        const compressed = new Uint8Array(arrayBuffer, dataOffset, compSize);
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        writer.write(compressed);
        writer.close();
        const reader = ds.readable.getReader();
        const chunks = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
        const totalLen = chunks.reduce((s, c) => s + c.length, 0);
        data = new Uint8Array(totalLen);
        let pos = 0;
        for (const chunk of chunks) {
          data.set(chunk, pos);
          pos += chunk.length;
        }
      } else {
        throw new Error(`Unsupported compression method ${method} for ${name}`);
      }
      
      // Strip the top-level folder name from the path
      const parts = name.split('/');
      if (parts.length > 1) {
        const relativePath = parts.slice(1).join('/');
        if (relativePath) files.set(relativePath, data);
      } else {
        files.set(name, data);
      }
    }
    
    offset += 46 + nameLen + extraLen + commentLen;
  }
  
  return files;
}

function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function verifyPackage(files) {
  const results = {
    manifestFound: false,
    manifestSealFound: false,
    manifestSealValid: false,
    manifestParsed: false,
    manifest: null,
    rootHashValid: false,
    signatureFound: false,
    signatureValid: null, // null = not checked, true/false = checked
    signatureError: null,
    artifacts: [],
    errors: [],
  };
  
  // 1. Check for MANIFEST.json
  if (!files.has('MANIFEST.json')) {
    results.errors.push('MANIFEST.json not found in package');
    return results;
  }
  results.manifestFound = true;
  
  const manifestBytes = files.get('MANIFEST.json');
  const manifestText = new TextDecoder().decode(manifestBytes);
  
  // 2. Verify manifest seal
  if (files.has('MANIFEST.json.sha256')) {
    results.manifestSealFound = true;
    const sealText = new TextDecoder().decode(files.get('MANIFEST.json.sha256'));
    const expectedHash = sealText.trim().split(/\s+/)[0];
    const actualHash = await sha256Hex(manifestBytes);
    results.manifestSealValid = expectedHash === actualHash;
    results.expectedManifestHash = expectedHash;
    results.actualManifestHash = actualHash;
    if (!results.manifestSealValid) {
      results.errors.push(`Manifest seal mismatch: expected ${expectedHash}, got ${actualHash}`);
    }
  } else {
    results.errors.push('MANIFEST.json.sha256 not found');
  }
  
  // 3. Parse manifest
  try {
    results.manifest = JSON.parse(manifestText);
    results.manifestParsed = true;
  } catch (e) {
    results.errors.push(`Failed to parse MANIFEST.json: ${e.message}`);
    return results;
  }
  
  // 4. Verify root hash
  if (results.manifest.artifacts && results.manifest.root_hash) {
    const artifactEntries = results.manifest.artifacts
      .filter(a => a.sha256 && a.path)
      .map(a => ({ path: a.path, sha256: a.sha256 }));
    const computedRoot = await rootHash(artifactEntries);
    results.rootHashValid = computedRoot === results.manifest.root_hash.value;
    results.expectedRootHash = results.manifest.root_hash.value;
    results.computedRootHash = computedRoot;
    if (!results.rootHashValid) {
      results.errors.push(`Root hash mismatch: expected ${results.manifest.root_hash.value}, got ${computedRoot}`);
    }
  }
  
  // 5. Verify each artifact
  if (results.manifest.artifacts) {
    for (const artifact of results.manifest.artifacts) {
      const entry = {
        path: artifact.path,
        expected: artifact.sha256,
        actual: null,
        valid: false,
        found: false,
        size: artifact.byte_size,
      };
      
      if (files.has(artifact.path)) {
        entry.found = true;
        const fileBytes = files.get(artifact.path);
        entry.actual = await sha256Hex(fileBytes);
        entry.valid = entry.actual === entry.expected;
        entry.actualSize = fileBytes.byteLength;
        if (!entry.valid) {
          results.errors.push(`Artifact ${artifact.path}: hash mismatch`);
        }
      } else {
        results.errors.push(`Artifact ${artifact.path}: file not found`);
      }
      
      results.artifacts.push(entry);
    }
  }
  
  // 6. Verify signature if present
  if (files.has('SIGNATURE.json')) {
    results.signatureFound = true;
    try {
      const sigText = new TextDecoder().decode(files.get('SIGNATURE.json'));
      const sigDoc = JSON.parse(sigText);
      
      if (sigDoc.public_key_jwk && sigDoc.signature) {
        const publicKey = await crypto.subtle.importKey(
          'jwk',
          sigDoc.public_key_jwk,
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['verify']
        );
        
        const signature = fromBase64(sigDoc.signature);
        const valid = await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          publicKey,
          signature,
          manifestBytes
        );
        
        results.signatureValid = valid;
        results.signerFingerprint = sigDoc.signer?.public_key_fingerprint_sha256;
        results.signerLabel = sigDoc.signer?.label;
        
        if (!valid) {
          results.errors.push('Signature verification failed');
        }
      } else {
        results.signatureError = 'Incomplete signature document';
        results.errors.push('SIGNATURE.json missing required fields');
      }
    } catch (e) {
      results.signatureError = e.message;
      results.errors.push(`Signature verification error: ${e.message}`);
    }
  }
  
  return results;
}

function renderResults(results) {
  const allPass = results.manifestFound && 
                  results.manifestSealValid && 
                  results.manifestParsed && 
                  results.rootHashValid &&
                  results.artifacts.every(a => a.valid) &&
                  (results.signatureFound ? results.signatureValid : true);
  
  const status = allPass ? 'pass' : 'fail';
  const statusIcon = allPass ? '✓' : '✗';
  const statusText = allPass ? 'Package verification PASSED' : 'Package verification FAILED';
  
  let html = `<div class="result ${status}">`;
  html += `<div class="result-head">${statusIcon} ${statusText}</div>`;
  
  html += '<ul class="check-list">';
  
  // Manifest found
  html += `<li><span class="icon ${results.manifestFound ? 'pass' : 'fail'}">${results.manifestFound ? '✓' : '✗'}</span> MANIFEST.json ${results.manifestFound ? 'found' : 'not found'}</li>`;
  
  // Manifest seal
  if (results.manifestSealFound) {
    html += `<li><span class="icon ${results.manifestSealValid ? 'pass' : 'fail'}">${results.manifestSealValid ? '✓' : '✗'}</span> Manifest seal ${results.manifestSealValid ? 'valid' : 'INVALID'}</li>`;
  } else {
    html += `<li><span class="icon fail">✗</span> Manifest seal file missing</li>`;
  }
  
  // Root hash
  if (results.manifestParsed) {
    html += `<li><span class="icon ${results.rootHashValid ? 'pass' : 'fail'}">${results.rootHashValid ? '✓' : '✗'}</span> Root hash ${results.rootHashValid ? 'valid' : 'INVALID'}</li>`;
  }
  
  // Artifacts
  const validArtifacts = results.artifacts.filter(a => a.valid).length;
  const totalArtifacts = results.artifacts.length;
  const allArtifactsValid = validArtifacts === totalArtifacts;
  html += `<li><span class="icon ${allArtifactsValid ? 'pass' : 'fail'}">${allArtifactsValid ? '✓' : '✗'}</span> Artifacts: ${validArtifacts}/${totalArtifacts} valid</li>`;
  
  // Signature
  if (results.signatureFound) {
    if (results.signatureValid === true) {
      html += `<li><span class="icon pass">✓</span> Signature valid (${results.signerLabel || 'unknown signer'})</li>`;
    } else if (results.signatureValid === false) {
      html += `<li><span class="icon fail">✗</span> Signature INVALID</li>`;
    } else {
      html += `<li><span class="icon fail">✗</span> Signature error: ${results.signatureError}</li>`;
    }
  } else {
    html += `<li><span class="icon skip">○</span> Package not signed</li>`;
  }
  
  html += '</ul>';
  
  // Artifact details
  if (results.artifacts.length > 0) {
    html += '<details class="details"><summary>Artifact details</summary>';
    html += '<table class="artifact-table"><thead><tr><th>File</th><th>Status</th><th>Size</th><th>Hash</th></tr></thead><tbody>';
    for (const a of results.artifacts) {
      const statusClass = a.valid ? 'pass' : 'fail';
      const statusText = a.found ? (a.valid ? 'OK' : 'MISMATCH') : 'MISSING';
      html += `<tr>
        <td>${a.path}</td>
        <td class="${statusClass}">${statusText}</td>
        <td>${a.found ? a.actualSize?.toLocaleString() : '—'}</td>
        <td class="hash">${a.valid ? a.expected?.slice(0, 16) + '…' : (a.actual ? `expected ${a.expected?.slice(0, 8)}… got ${a.actual?.slice(0, 8)}…` : '—')}</td>
      </tr>`;
    }
    html += '</tbody></table></details>';
  }
  
  // Errors
  if (results.errors.length > 0) {
    html += '<details class="details" open><summary>Errors</summary>';
    html += '<pre>' + results.errors.join('\n') + '</pre></details>';
  }
  
  // Manifest info
  if (results.manifest) {
    html += '<details class="details"><summary>Package info</summary>';
    html += '<pre>' + JSON.stringify({
      schema: results.manifest.schema,
      collection_id: results.manifest.collection?.collection_id,
      case_id: results.manifest.case?.case_id,
      examiner: results.manifest.case?.examiner,
      started_utc: results.manifest.collection?.started_utc,
      completed_utc: results.manifest.collection?.completed_utc,
      artifact_count: results.manifest.totals?.artifact_count,
      total_bytes: results.manifest.totals?.total_bytes,
      signed: results.manifest.signature?.signed,
    }, null, 2) + '</pre></details>';
  }
  
  html += '</div>';
  return html;
}

async function handleFile(file) {
  const resultDiv = $('result');
  resultDiv.style.display = 'block';
  resultDiv.innerHTML = '<div class="result pending"><div class="result-head">⏳ Verifying package…</div></div>';
  
  try {
    const buffer = await file.arrayBuffer();
    const files = await readZip(buffer);
    const results = await verifyPackage(files);
    resultDiv.innerHTML = renderResults(results);
  } catch (e) {
    resultDiv.innerHTML = `<div class="result fail">
      <div class="result-head">✗ Verification failed</div>
      <p>Error: ${e.message}</p>
    </div>`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  $('version').textContent = 'v' + (chrome?.runtime?.getManifest?.()?.version || '0.4.0');
  
  const dropzone = $('dropzone');
  const fileInput = $('fileInput');
  
  dropzone.addEventListener('click', () => fileInput.click());
  
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });
  
  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });
  
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) handleFile(file);
    e.target.value = '';
  });
});
