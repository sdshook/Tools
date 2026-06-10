// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// BAI: Content script for collecting web storage and service worker data.
// Injected into tabs to access origin-scoped data that extensions cannot
// directly read. All operations are read-only.

(function() {
  'use strict';

  // Respond to messages from the extension
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'collectStorage') {
      collectStorage().then(sendResponse);
      return true; // Keep channel open for async response
    }
    if (request.action === 'collectIndexedDB') {
      collectIndexedDB().then(sendResponse);
      return true;
    }
    if (request.action === 'collectServiceWorkers') {
      collectServiceWorkers().then(sendResponse);
      return true;
    }
    if (request.action === 'collectCacheStorage') {
      collectCacheStorage().then(sendResponse);
      return true;
    }
    if (request.action === 'collectStorageEstimate') {
      collectStorageEstimate().then(sendResponse);
      return true;
    }
    if (request.action === 'collectPerformance') {
      collectPerformance().then(sendResponse);
      return true;
    }
    if (request.action === 'collectWebAuthn') {
      collectWebAuthn().then(sendResponse);
      return true;
    }
    if (request.action === 'collectMediaDevices') {
      collectMediaDevices().then(sendResponse);
      return true;
    }
    if (request.action === 'collectIndexedDBFull') {
      collectIndexedDBFull().then(sendResponse);
      return true;
    }
  });

  /**
   * Collect localStorage and sessionStorage for this origin.
   */
  async function collectStorage() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      localStorage: null,
      sessionStorage: null,
      error: null,
    };

    try {
      // localStorage
      if (window.localStorage) {
        const local = {};
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          try {
            local[key] = localStorage.getItem(key);
          } catch (e) {
            local[key] = `[Error reading: ${e.message}]`;
          }
        }
        result.localStorage = {
          itemCount: localStorage.length,
          items: local,
          totalSize: JSON.stringify(local).length,
        };
      }
    } catch (e) {
      result.localStorage = { error: e.message };
    }

    try {
      // sessionStorage
      if (window.sessionStorage) {
        const session = {};
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          try {
            session[key] = sessionStorage.getItem(key);
          } catch (e) {
            session[key] = `[Error reading: ${e.message}]`;
          }
        }
        result.sessionStorage = {
          itemCount: sessionStorage.length,
          items: session,
          totalSize: JSON.stringify(session).length,
        };
      }
    } catch (e) {
      result.sessionStorage = { error: e.message };
    }

    return result;
  }

  /**
   * Enumerate IndexedDB databases and their object stores for this origin.
   * Does not dump full contents to avoid performance issues.
   */
  async function collectIndexedDB() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      databases: [],
      error: null,
    };

    try {
      // indexedDB.databases() is available in modern browsers
      if (indexedDB && typeof indexedDB.databases === 'function') {
        const dbList = await indexedDB.databases();
        
        for (const dbInfo of dbList) {
          const dbRecord = {
            name: dbInfo.name,
            version: dbInfo.version,
            objectStores: [],
            error: null,
          };

          try {
            // Open database read-only to enumerate object stores
            const db = await new Promise((resolve, reject) => {
              const req = indexedDB.open(dbInfo.name);
              req.onsuccess = () => resolve(req.result);
              req.onerror = () => reject(req.error);
              // Don't trigger upgrade
              req.onupgradeneeded = (e) => {
                e.target.transaction.abort();
                reject(new Error('Cannot open without upgrade'));
              };
            });

            // Enumerate object stores
            const storeNames = Array.from(db.objectStoreNames);
            for (const storeName of storeNames) {
              try {
                const tx = db.transaction(storeName, 'readonly');
                const store = tx.objectStore(storeName);
                const countReq = store.count();
                const count = await new Promise((resolve) => {
                  countReq.onsuccess = () => resolve(countReq.result);
                  countReq.onerror = () => resolve(-1);
                });
                
                dbRecord.objectStores.push({
                  name: storeName,
                  keyPath: store.keyPath,
                  autoIncrement: store.autoIncrement,
                  indexNames: Array.from(store.indexNames),
                  recordCount: count,
                });
              } catch (e) {
                dbRecord.objectStores.push({
                  name: storeName,
                  error: e.message,
                });
              }
            }

            db.close();
          } catch (e) {
            dbRecord.error = e.message;
          }

          result.databases.push(dbRecord);
        }
      } else {
        result.error = 'indexedDB.databases() not available in this browser';
      }
    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Enumerate registered Service Workers for this origin.
   */
  async function collectServiceWorkers() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      serviceWorkers: [],
      error: null,
    };

    try {
      if ('serviceWorker' in navigator) {
        const registrations = await navigator.serviceWorker.getRegistrations();
        
        for (const reg of registrations) {
          result.serviceWorkers.push({
            scope: reg.scope,
            updateViaCache: reg.updateViaCache,
            installing: reg.installing ? {
              scriptURL: reg.installing.scriptURL,
              state: reg.installing.state,
            } : null,
            waiting: reg.waiting ? {
              scriptURL: reg.waiting.scriptURL,
              state: reg.waiting.state,
            } : null,
            active: reg.active ? {
              scriptURL: reg.active.scriptURL,
              state: reg.active.state,
            } : null,
          });
        }
      } else {
        result.error = 'Service Workers not supported';
      }
    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Enumerate Cache Storage caches and their contents.
   * Lists cache names and URLs stored in each cache.
   */
  async function collectCacheStorage() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      caches: [],
      error: null,
    };

    try {
      if ('caches' in window) {
        const cacheNames = await caches.keys();
        
        for (const cacheName of cacheNames) {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();
          
          result.caches.push({
            name: cacheName,
            entryCount: requests.length,
            urls: requests.slice(0, 100).map(r => r.url), // Limit to first 100 URLs
            truncated: requests.length > 100,
          });
        }
      } else {
        result.error = 'Cache Storage not supported';
      }
    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Get storage estimate for this origin.
   * Shows quota usage which can indicate significant stored data.
   */
  async function collectStorageEstimate() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      estimate: null,
      error: null,
    };

    try {
      if (navigator.storage && navigator.storage.estimate) {
        const estimate = await navigator.storage.estimate();
        result.estimate = {
          quota: estimate.quota,
          usage: estimate.usage,
          usagePercent: estimate.quota ? ((estimate.usage / estimate.quota) * 100).toFixed(2) : null,
          usageDetails: estimate.usageDetails || null,
        };
      } else {
        result.error = 'Storage estimate not supported';
      }
    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Collect performance and navigation timing data.
   * Can reveal redirects and timing anomalies (AiTM indicators).
   */
  async function collectPerformance() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      navigation: null,
      resources: [],
      error: null,
    };

    try {
      // Navigation timing
      const navEntries = performance.getEntriesByType('navigation');
      if (navEntries.length > 0) {
        const nav = navEntries[0];
        result.navigation = {
          type: nav.type,
          redirectCount: nav.redirectCount,
          startTime: nav.startTime,
          redirectStart: nav.redirectStart,
          redirectEnd: nav.redirectEnd,
          fetchStart: nav.fetchStart,
          domainLookupStart: nav.domainLookupStart,
          domainLookupEnd: nav.domainLookupEnd,
          connectStart: nav.connectStart,
          secureConnectionStart: nav.secureConnectionStart,
          connectEnd: nav.connectEnd,
          requestStart: nav.requestStart,
          responseStart: nav.responseStart,
          responseEnd: nav.responseEnd,
          domInteractive: nav.domInteractive,
          domContentLoadedEventEnd: nav.domContentLoadedEventEnd,
          loadEventEnd: nav.loadEventEnd,
          transferSize: nav.transferSize,
          encodedBodySize: nav.encodedBodySize,
          decodedBodySize: nav.decodedBodySize,
          serverTiming: nav.serverTiming || [],
        };
      }

      // Resource timing (last 50 resources)
      const resources = performance.getEntriesByType('resource');
      result.resources = resources.slice(-50).map(r => ({
        name: r.name,
        initiatorType: r.initiatorType,
        startTime: r.startTime,
        duration: r.duration,
        transferSize: r.transferSize,
        encodedBodySize: r.encodedBodySize,
      }));
      result.resourceCount = resources.length;
      result.resourcesTruncated = resources.length > 50;

    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Collect WebAuthn/FIDO capabilities and any discoverable credentials info.
   * Critical for AiTM detection: shows if passkeys/security keys are configured.
   */
  async function collectWebAuthn() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      webauthn: {
        supported: false,
        platformAuthenticatorAvailable: null,
        conditionalMediationAvailable: null,
        userVerifyingPlatformAuthenticatorAvailable: null,
      },
      credentialManagement: {
        supported: false,
        preventSilentAccess: null,
      },
      error: null,
    };

    try {
      // Check WebAuthn support
      if (window.PublicKeyCredential) {
        result.webauthn.supported = true;

        // Check if platform authenticator is available (TouchID, Windows Hello, etc.)
        if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
          try {
            result.webauthn.userVerifyingPlatformAuthenticatorAvailable = 
              await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          } catch (e) {
            result.webauthn.userVerifyingPlatformAuthenticatorAvailable = `error: ${e.message}`;
          }
        }

        // Check conditional mediation (passkey autofill) support
        if (PublicKeyCredential.isConditionalMediationAvailable) {
          try {
            result.webauthn.conditionalMediationAvailable = 
              await PublicKeyCredential.isConditionalMediationAvailable();
          } catch (e) {
            result.webauthn.conditionalMediationAvailable = `error: ${e.message}`;
          }
        }
      }

      // Check Credential Management API
      if (navigator.credentials) {
        result.credentialManagement.supported = true;
        // Note: Cannot enumerate credentials without user gesture
        // But we can check if the API exists
      }

    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Enumerate media devices (cameras, microphones, speakers).
   * Shows what devices are available/granted.
   */
  async function collectMediaDevices() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      devices: [],
      permissions: {
        camera: null,
        microphone: null,
      },
      error: null,
    };

    try {
      // Enumerate devices (labels hidden without permission)
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        const devices = await navigator.mediaDevices.enumerateDevices();
        result.devices = devices.map(d => ({
          deviceId: d.deviceId ? d.deviceId.substring(0, 16) + '...' : null,
          kind: d.kind,
          label: d.label || '[permission required]',
          groupId: d.groupId ? d.groupId.substring(0, 16) + '...' : null,
        }));
      }

      // Check permission status if available
      if (navigator.permissions && navigator.permissions.query) {
        try {
          const camPerm = await navigator.permissions.query({ name: 'camera' });
          result.permissions.camera = camPerm.state;
        } catch (e) { /* permission query not supported for camera */ }

        try {
          const micPerm = await navigator.permissions.query({ name: 'microphone' });
          result.permissions.microphone = micPerm.state;
        } catch (e) { /* permission query not supported for microphone */ }
      }

    } catch (e) {
      result.error = e.message;
    }

    return result;
  }

  /**
   * Full IndexedDB dump - exports all data from databases.
   * Complete dump for forensic purposes.
   */
  async function collectIndexedDBFull() {
    const result = {
      origin: window.location.origin,
      url: window.location.href,
      databases: [],
      error: null,
    };

    try {
      if (!indexedDB || typeof indexedDB.databases !== 'function') {
        result.error = 'indexedDB.databases() not available';
        return result;
      }

      const dbList = await indexedDB.databases();

      for (const dbInfo of dbList) {
        const dbRecord = {
          name: dbInfo.name,
          version: dbInfo.version,
          objectStores: [],
          error: null,
        };

        try {
          const db = await new Promise((resolve, reject) => {
            const req = indexedDB.open(dbInfo.name);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
            req.onupgradeneeded = (e) => {
              e.target.transaction.abort();
              reject(new Error('Cannot open without upgrade'));
            };
          });

          const storeNames = Array.from(db.objectStoreNames);
          
          for (const storeName of storeNames) {
            const storeRecord = {
              name: storeName,
              keyPath: null,
              autoIncrement: false,
              indexNames: [],
              totalCount: 0,
              records: [],
              error: null,
            };

            try {
              const tx = db.transaction(storeName, 'readonly');
              const store = tx.objectStore(storeName);
              
              storeRecord.keyPath = store.keyPath;
              storeRecord.autoIncrement = store.autoIncrement;
              storeRecord.indexNames = Array.from(store.indexNames);

              // Get total count
              const countReq = store.count();
              storeRecord.totalCount = await new Promise((resolve) => {
                countReq.onsuccess = () => resolve(countReq.result);
                countReq.onerror = () => resolve(-1);
              });

              // Get ALL records (complete dump)
              const records = [];
              const cursorReq = store.openCursor();
              
              await new Promise((resolve) => {
                cursorReq.onsuccess = (e) => {
                  const cursor = e.target.result;
                  if (cursor) {
                    try {
                      // Attempt to serialize the value
                      const serialized = JSON.parse(JSON.stringify({
                        key: cursor.key,
                        value: cursor.value,
                      }));
                      records.push(serialized);
                    } catch (serErr) {
                      records.push({
                        key: cursor.key,
                        value: '[Serialization error]',
                        error: serErr.message,
                      });
                    }
                    cursor.continue();
                  } else {
                    resolve();
                  }
                };
                cursorReq.onerror = () => resolve();
              });

              storeRecord.records = records;

            } catch (e) {
              storeRecord.error = e.message;
            }

            dbRecord.objectStores.push(storeRecord);
          }

          db.close();

        } catch (e) {
          dbRecord.error = e.message;
        }

        result.databases.push(dbRecord);
      }

    } catch (e) {
      result.error = e.message;
    }

    return result;
  }
})();
