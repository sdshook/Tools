// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// Browser Audit Inventory — evidence collectors
//
// Each collector reads one artifact type through the official chrome.* APIs and
// returns plain data. Collectors do not write files or hash; that is the
// console's job, so the same captured bytes flow through hashing and writing
// without re-serialization.
//
// Known limitations are documented inline and surfaced in the manifest. This is
// a LIVE acquisition of the currently signed-in profile: it cannot reach saved
// passwords, deleted records, other OS users, or data outside this profile, and
// its own presence is part of the profile state.

const RESTRICTED_URL = /^(chrome|chrome-extension|chrome-untrusted|devtools|view-source|about|edge|file):/i;

/**
 * Full browsing history via windowed pagination. chrome.history.search caps
 * results per call, so we walk backwards in time using the oldest lastVisitTime
 * seen, de-duplicating by id. Very large histories with many identical
 * timestamps may still truncate at the boundary; that case is flagged.
 */
export async function collectHistory(onProgress) {
  const PAGE = 1000;
  const seen = new Set();
  const items = [];
  let endTime = Date.now();
  let truncated = false;
  let guard = 0;

  while (true) {
    if (++guard > 5000) { truncated = true; break; } // hard safety stop
    const batch = await chrome.history.search({
      text: '',
      startTime: 0,
      endTime,
      maxResults: PAGE,
    });
    if (batch.length === 0) break;

    let oldest = endTime;
    for (const it of batch) {
      if (!seen.has(it.id)) {
        seen.add(it.id);
        items.push(it);
      }
      if (typeof it.lastVisitTime === 'number' && it.lastVisitTime < oldest) {
        oldest = it.lastVisitTime;
      }
    }
    onProgress?.(`history: ${items.length} URLs`);

    if (batch.length < PAGE) break;
    const nextEnd = oldest - 1;
    if (nextEnd >= endTime) { truncated = true; break; } // no time progress
    endTime = nextEnd;
  }

  return {
    artifact_type: 'history',
    source_api: 'chrome.history.search',
    record_count: items.length,
    truncated,
    records: items,
  };
}

/** All cookies across every cookie store, including HttpOnly. */
export async function collectCookies(onProgress) {
  const stores = await chrome.cookies.getAllCookieStores();
  const out = [];
  for (const store of stores) {
    const cookies = await chrome.cookies.getAll({ storeId: store.id });
    for (const c of cookies) out.push({ ...c, storeId: store.id });
    onProgress?.(`cookies: ${out.length} (store ${store.id})`);
  }
  return {
    artifact_type: 'cookies',
    source_api: 'chrome.cookies.getAll',
    record_count: out.length,
    cookie_stores: stores.map((s) => s.id),
    records: out,
  };
}

/** Download history records (metadata, not the downloaded bytes). */
export async function collectDownloads(onProgress) {
  const records = await chrome.downloads.search({});
  onProgress?.(`downloads: ${records.length}`);
  return {
    artifact_type: 'downloads',
    source_api: 'chrome.downloads.search',
    record_count: records.length,
    records,
  };
}

/**
 * Per-tab MHTML snapshots of every open, capturable tab. Restricted-scheme
 * tabs (chrome://, extension pages, etc.) cannot be captured and are recorded
 * as skipped rather than silently dropped. Returns metadata plus the raw MHTML
 * bytes for each captured tab so the console can write and hash them.
 */
export async function collectTabSnapshots(onProgress) {
  const tabs = await chrome.tabs.query({});
  const snapshots = [];
  for (const tab of tabs) {
    const meta = {
      tabId: tab.id,
      windowId: tab.windowId,
      index: tab.index,
      url: tab.url || tab.pendingUrl || '',
      title: tab.title || '',
    };

    if (!meta.url || RESTRICTED_URL.test(meta.url)) {
      snapshots.push({ ...meta, captured: false, reason: 'restricted-or-empty-url', bytes: null });
      onProgress?.(`snapshot skipped: ${meta.url || '(no url)'}`);
      continue;
    }

    try {
      const blob = await chrome.pageCapture.saveAsMHTML({ tabId: tab.id });
      const bytes = new Uint8Array(await blob.arrayBuffer());
      snapshots.push({ ...meta, captured: true, reason: null, bytes });
      onProgress?.(`snapshot: ${meta.title || meta.url}`);
    } catch (err) {
      snapshots.push({ ...meta, captured: false, reason: String(err?.message || err), bytes: null });
      onProgress?.(`snapshot failed: ${meta.url} (${err?.message || err})`);
    }
  }
  return {
    artifact_type: 'tab_snapshots',
    source_api: 'chrome.pageCapture.saveAsMHTML',
    record_count: snapshots.length,
    captured_count: snapshots.filter((s) => s.captured).length,
    snapshots,
  };
}

/**
 * Bookmarks tree via chrome.bookmarks.getTree. Recursively flattens the tree
 * structure into an array of bookmark/folder nodes with parent references.
 */
export async function collectBookmarks(onProgress) {
  const tree = await chrome.bookmarks.getTree();
  const records = [];
  
  function walk(nodes, parentId = null) {
    for (const node of nodes) {
      records.push({
        id: node.id,
        parentId: parentId,
        title: node.title || '',
        url: node.url || null, // null for folders
        dateAdded: node.dateAdded,
        dateGroupModified: node.dateGroupModified,
        isFolder: !node.url,
      });
      if (node.children) walk(node.children, node.id);
    }
  }
  walk(tree);
  onProgress?.(`bookmarks: ${records.length} items`);
  
  return {
    artifact_type: 'bookmarks',
    source_api: 'chrome.bookmarks.getTree',
    record_count: records.length,
    folder_count: records.filter(r => r.isFolder).length,
    bookmark_count: records.filter(r => !r.isFolder).length,
    records,
  };
}

/**
 * Installed extensions and apps via chrome.management.getAll.
 * Useful for identifying potentially malicious or suspicious extensions.
 */
export async function collectExtensions(onProgress) {
  const extensions = await chrome.management.getAll();
  const records = extensions.map(ext => ({
    id: ext.id,
    name: ext.name,
    shortName: ext.shortName,
    description: ext.description,
    version: ext.version,
    versionName: ext.versionName,
    type: ext.type,
    enabled: ext.enabled,
    installType: ext.installType,
    mayDisable: ext.mayDisable,
    mayEnable: ext.mayEnable,
    homepageUrl: ext.homepageUrl || null,
    updateUrl: ext.updateUrl || null,
    permissions: ext.permissions || [],
    hostPermissions: ext.hostPermissions || [],
    offlineEnabled: ext.offlineEnabled,
    isApp: ext.isApp,
  }));
  onProgress?.(`extensions: ${records.length} installed`);
  
  return {
    artifact_type: 'extensions',
    source_api: 'chrome.management.getAll',
    record_count: records.length,
    enabled_count: records.filter(r => r.enabled).length,
    disabled_count: records.filter(r => !r.enabled).length,
    records,
  };
}

/**
 * Recently closed tabs and windows via chrome.sessions.getRecentlyClosed.
 * Limited to the browser's session history retention.
 */
export async function collectSessions(onProgress) {
  const sessions = await chrome.sessions.getRecentlyClosed({ maxResults: 25 });
  const records = sessions.map(session => {
    if (session.tab) {
      return {
        type: 'tab',
        lastModified: session.lastModified,
        tab: {
          tabId: session.tab.sessionId,
          windowId: session.tab.windowId,
          url: session.tab.url || '',
          title: session.tab.title || '',
          favIconUrl: session.tab.favIconUrl || null,
          index: session.tab.index,
        },
      };
    } else if (session.window) {
      return {
        type: 'window',
        lastModified: session.lastModified,
        window: {
          sessionId: session.window.sessionId,
          tabCount: session.window.tabs?.length || 0,
          tabs: (session.window.tabs || []).map(t => ({
            url: t.url || '',
            title: t.title || '',
            index: t.index,
          })),
        },
      };
    }
    return { type: 'unknown', lastModified: session.lastModified };
  });
  onProgress?.(`sessions: ${records.length} recently closed`);
  
  return {
    artifact_type: 'sessions',
    source_api: 'chrome.sessions.getRecentlyClosed',
    record_count: records.length,
    tab_count: records.filter(r => r.type === 'tab').length,
    window_count: records.filter(r => r.type === 'window').length,
    records,
  };
}

/**
 * Top sites (most visited) via chrome.topSites.get.
 * Returns the "new tab" page's top sites list.
 */
export async function collectTopSites(onProgress) {
  const sites = await chrome.topSites.get();
  const records = sites.map((site, index) => ({
    rank: index + 1,
    url: site.url,
    title: site.title,
  }));
  onProgress?.(`topSites: ${records.length} sites`);
  
  return {
    artifact_type: 'top_sites',
    source_api: 'chrome.topSites.get',
    record_count: records.length,
    records,
  };
}

/**
 * Proxy settings via chrome.proxy.settings.get.
 * Critical for AiTM detection: shows if traffic is routed through a proxy.
 */
export async function collectProxySettings(onProgress) {
  const settings = await new Promise((resolve) => {
    chrome.proxy.settings.get({}, resolve);
  });
  onProgress?.('proxy: settings collected');
  
  return {
    artifact_type: 'proxy_settings',
    source_api: 'chrome.proxy.settings.get',
    record_count: 1,
    levelOfControl: settings.levelOfControl,
    value: settings.value,
    notes: settings.levelOfControl === 'controlled_by_other_extensions' 
      ? 'WARNING: Proxy controlled by another extension' : null,
  };
}

/**
 * Privacy settings via chrome.privacy.
 * Shows security-relevant browser settings.
 */
export async function collectPrivacySettings(onProgress) {
  const settings = {};
  
  // Network settings
  if (chrome.privacy.network) {
    try {
      settings.networkPredictionEnabled = await new Promise(r => 
        chrome.privacy.network.networkPredictionEnabled.get({}, r));
      settings.webRTCIPHandlingPolicy = await new Promise(r => 
        chrome.privacy.network.webRTCIPHandlingPolicy?.get({}, r));
    } catch (e) { /* API may not be available */ }
  }
  
  // Services settings
  if (chrome.privacy.services) {
    try {
      settings.safeBrowsingEnabled = await new Promise(r => 
        chrome.privacy.services.safeBrowsingEnabled?.get({}, r));
      settings.safeBrowsingExtendedReportingEnabled = await new Promise(r => 
        chrome.privacy.services.safeBrowsingExtendedReportingEnabled?.get({}, r));
      settings.spellingServiceEnabled = await new Promise(r => 
        chrome.privacy.services.spellingServiceEnabled?.get({}, r));
      settings.searchSuggestEnabled = await new Promise(r => 
        chrome.privacy.services.searchSuggestEnabled?.get({}, r));
      settings.translationServiceEnabled = await new Promise(r => 
        chrome.privacy.services.translationServiceEnabled?.get({}, r));
    } catch (e) { /* API may not be available */ }
  }
  
  // Website settings
  if (chrome.privacy.websites) {
    try {
      settings.thirdPartyCookiesAllowed = await new Promise(r => 
        chrome.privacy.websites.thirdPartyCookiesAllowed?.get({}, r));
      settings.doNotTrackEnabled = await new Promise(r => 
        chrome.privacy.websites.doNotTrackEnabled?.get({}, r));
      settings.hyperlinkAuditingEnabled = await new Promise(r => 
        chrome.privacy.websites.hyperlinkAuditingEnabled?.get({}, r));
      settings.referrersEnabled = await new Promise(r => 
        chrome.privacy.websites.referrersEnabled?.get({}, r));
    } catch (e) { /* API may not be available */ }
  }
  
  // Filter out undefined values
  const records = Object.fromEntries(
    Object.entries(settings).filter(([_, v]) => v !== undefined)
  );
  
  onProgress?.(`privacy: ${Object.keys(records).length} settings collected`);
  
  return {
    artifact_type: 'privacy_settings',
    source_api: 'chrome.privacy',
    record_count: Object.keys(records).length,
    records,
  };
}

/**
 * Content settings for common permission types.
 * Shows per-site permissions that could indicate compromise or social engineering.
 */
export async function collectContentSettings(onProgress) {
  const contentTypes = [
    'cookies', 'javascript', 'notifications', 'popups', 
    'location', 'camera', 'microphone', 'automaticDownloads'
  ];
  
  const settings = {};
  
  for (const type of contentTypes) {
    try {
      if (chrome.contentSettings[type]) {
        // Get the default setting
        const defaultSetting = await new Promise((resolve) => {
          chrome.contentSettings[type].get({ primaryUrl: 'https://*' }, resolve);
        });
        settings[type] = {
          default: defaultSetting?.setting || 'unknown',
        };
      }
    } catch (e) {
      // Some content types may not be available
    }
  }
  
  onProgress?.(`contentSettings: ${Object.keys(settings).length} types collected`);
  
  return {
    artifact_type: 'content_settings',
    source_api: 'chrome.contentSettings',
    record_count: Object.keys(settings).length,
    records: settings,
    notes: 'Default settings only; per-site exceptions require individual URL queries',
  };
}

/**
 * Default search engine settings.
 * Useful for detecting search engine hijacking.
 */
export async function collectSearchEngines(onProgress) {
  let searchEngines = [];
  let error = null;
  
  try {
    // chrome.search.query is available but chrome.searchEngines may not be
    // We can detect the default by checking what happens with a search
    // For now, we just note the API availability
    if (chrome.search) {
      searchEngines.push({
        note: 'chrome.search API available',
        canQuery: typeof chrome.search.query === 'function',
      });
    }
  } catch (e) {
    error = e.message;
  }
  
  onProgress?.('search: settings collected');
  
  return {
    artifact_type: 'search_settings',
    source_api: 'chrome.search',
    record_count: searchEngines.length,
    records: searchEngines,
    error,
    notes: 'Full search engine enumeration requires chrome.searchEngines API (limited availability)',
  };
}

/**
 * Detailed visit information for history URLs.
 * Provides visit count, transition types, and timestamps per URL.
 */
export async function collectVisitDetails(onProgress) {
  const PAGE = 500;
  const seen = new Set();
  const urlVisits = [];
  let endTime = Date.now();
  let urlCount = 0;
  let totalVisits = 0;

  // First, collect URLs from history
  while (urlCount < 1000) { // Limit to 1000 URLs for performance
    const batch = await chrome.history.search({
      text: '',
      startTime: 0,
      endTime,
      maxResults: PAGE,
    });
    if (batch.length === 0) break;

    let oldest = endTime;
    for (const item of batch) {
      if (!seen.has(item.id)) {
        seen.add(item.id);
        urlCount++;
        
        // Get detailed visits for this URL
        try {
          const visits = await chrome.history.getVisits({ url: item.url });
          const visitDetails = visits.map(v => ({
            visitId: v.visitId,
            visitTime: v.visitTime,
            referringVisitId: v.referringVisitId,
            transition: v.transition,
          }));
          
          urlVisits.push({
            url: item.url,
            title: item.title,
            visitCount: item.visitCount,
            typedCount: item.typedCount,
            lastVisitTime: item.lastVisitTime,
            visits: visitDetails,
          });
          
          totalVisits += visits.length;
        } catch (e) {
          urlVisits.push({
            url: item.url,
            error: e.message,
          });
        }
      }
      if (typeof item.lastVisitTime === 'number' && item.lastVisitTime < oldest) {
        oldest = item.lastVisitTime;
      }
    }
    
    onProgress?.(`visitDetails: ${urlCount} URLs, ${totalVisits} visits`);
    
    if (batch.length < PAGE) break;
    const nextEnd = oldest - 1;
    if (nextEnd >= endTime) break;
    endTime = nextEnd;
  }

  return {
    artifact_type: 'visit_details',
    source_api: 'chrome.history.getVisits',
    record_count: urlVisits.length,
    total_visits: totalVisits,
    records: urlVisits,
  };
}

/**
 * Collect localStorage and sessionStorage from all open tabs.
 * Requires content script injection.
 */
export async function collectWebStorage(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;

  for (const tab of tabs) {
    // Skip restricted URLs
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      // Send message to content script
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectStorage' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`webStorage: ${collected} tabs collected`);
      }
    } catch (e) {
      // Content script may not be loaded or tab is not accessible
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'web_storage',
    source_api: 'localStorage/sessionStorage via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
  };
}

/**
 * Collect IndexedDB database information from all open tabs.
 * Requires content script injection.
 */
export async function collectIndexedDBInfo(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectIndexedDB' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`indexedDB: ${collected} tabs collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'indexeddb',
    source_api: 'IndexedDB via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
  };
}

/**
 * Collect Service Worker registrations from all open tabs.
 * Requires content script injection.
 */
export async function collectServiceWorkers(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;
  const seenOrigins = new Set();

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    // Only collect once per origin
    try {
      const origin = new URL(tab.url).origin;
      if (seenOrigins.has(origin)) continue;
      seenOrigins.add(origin);
    } catch (e) {
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectServiceWorkers' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`serviceWorkers: ${collected} origins collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'service_workers',
    source_api: 'navigator.serviceWorker via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
  };
}

/**
 * Collect Cache Storage contents from all open tabs.
 * Requires content script injection.
 */
export async function collectCacheStorage(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;
  const seenOrigins = new Set();

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    // Only collect once per origin
    try {
      const origin = new URL(tab.url).origin;
      if (seenOrigins.has(origin)) continue;
      seenOrigins.add(origin);
    } catch (e) {
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectCacheStorage' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`cacheStorage: ${collected} origins collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'cache_storage',
    source_api: 'Cache Storage API via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
  };
}

/**
 * Collect storage estimates from all open tabs.
 * Shows quota usage per origin.
 */
export async function collectStorageEstimates(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;
  const seenOrigins = new Set();

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      const origin = new URL(tab.url).origin;
      if (seenOrigins.has(origin)) continue;
      seenOrigins.add(origin);
    } catch (e) {
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectStorageEstimate' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`storageEstimate: ${collected} origins collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'storage_estimates',
    source_api: 'navigator.storage.estimate via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
  };
}

/**
 * Collect performance timing from all open tabs.
 * Can reveal redirects and timing anomalies indicating AiTM.
 */
export async function collectPerformanceTiming(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectPerformance' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`performance: ${collected} tabs collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'performance_timing',
    source_api: 'Performance API via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
    notes: 'Redirect counts and timing can indicate AiTM proxying',
  };
}

/**
 * Collect permissions granted to extensions.
 * Shows what capabilities extensions have been given.
 */
export async function collectPermissions(onProgress) {
  let permissions = null;
  let error = null;
  
  try {
    permissions = await chrome.permissions.getAll();
    onProgress?.('permissions: collected');
  } catch (e) {
    error = e.message;
  }
  
  return {
    artifact_type: 'permissions',
    source_api: 'chrome.permissions.getAll',
    record_count: (permissions?.permissions?.length || 0) + (permissions?.origins?.length || 0),
    permissions: permissions?.permissions || [],
    origins: permissions?.origins || [],
    error,
  };
}

/**
 * Collect all open windows and their states.
 */
export async function collectWindows(onProgress) {
  const windows = await chrome.windows.getAll({ populate: false });
  onProgress?.(`windows: ${windows.length} collected`);
  
  return {
    artifact_type: 'windows',
    source_api: 'chrome.windows.getAll',
    record_count: windows.length,
    records: windows.map(w => ({
      id: w.id,
      type: w.type,
      state: w.state,
      focused: w.focused,
      incognito: w.incognito,
      alwaysOnTop: w.alwaysOnTop,
      left: w.left,
      top: w.top,
      width: w.width,
      height: w.height,
    })),
  };
}

/**
 * Detailed tab information including audio/mute state.
 */
export async function collectTabsDetailed(onProgress) {
  const tabs = await chrome.tabs.query({});
  onProgress?.(`tabsDetailed: ${tabs.length} collected`);
  
  return {
    artifact_type: 'tabs_detailed',
    source_api: 'chrome.tabs.query',
    record_count: tabs.length,
    records: tabs.map(t => ({
      id: t.id,
      windowId: t.windowId,
      index: t.index,
      url: t.url,
      title: t.title,
      active: t.active,
      pinned: t.pinned,
      audible: t.audible,
      muted: t.mutedInfo?.muted,
      mutedReason: t.mutedInfo?.reason,
      incognito: t.incognito,
      status: t.status,
      discarded: t.discarded,
      autoDiscardable: t.autoDiscardable,
      groupId: t.groupId,
      lastAccessed: t.lastAccessed,
    })),
  };
}

/**
 * Collect WebAuthn/FIDO capabilities from all open tabs.
 * Critical for AiTM: shows if passkeys/security keys are available.
 */
export async function collectWebAuthnInfo(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;
  const seenOrigins = new Set();

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      const origin = new URL(tab.url).origin;
      if (seenOrigins.has(origin)) continue;
      seenOrigins.add(origin);
    } catch (e) {
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectWebAuthn' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`webauthn: ${collected} origins collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'webauthn_capabilities',
    source_api: 'WebAuthn/Credential Management API via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
    notes: 'Shows if passkeys/security keys are configured per origin',
  };
}

/**
 * Collect media device enumeration from all open tabs.
 */
export async function collectMediaDevicesInfo(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;
  const seenOrigins = new Set();

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      const origin = new URL(tab.url).origin;
      if (seenOrigins.has(origin)) continue;
      seenOrigins.add(origin);
    } catch (e) {
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { action: 'collectMediaDevices' });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`mediaDevices: ${collected} origins collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'media_devices',
    source_api: 'navigator.mediaDevices via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
  };
}

/**
 * Full IndexedDB dump with actual record data from all open tabs.
 * Complete dump for forensic purposes.
 */
export async function collectIndexedDBFull(onProgress) {
  const tabs = await chrome.tabs.query({});
  const results = [];
  let collected = 0;
  let skipped = 0;
  const seenOrigins = new Set();

  for (const tab of tabs) {
    if (!tab.url || RESTRICTED_URL.test(tab.url)) {
      skipped++;
      continue;
    }

    try {
      const origin = new URL(tab.url).origin;
      if (seenOrigins.has(origin)) continue;
      seenOrigins.add(origin);
    } catch (e) {
      continue;
    }

    try {
      const response = await chrome.tabs.sendMessage(tab.id, { 
        action: 'collectIndexedDBFull',
      });
      if (response) {
        results.push(response);
        collected++;
        onProgress?.(`indexedDBFull: ${collected} origins collected`);
      }
    } catch (e) {
      results.push({
        origin: tab.url,
        tabId: tab.id,
        error: e.message,
      });
    }
  }

  return {
    artifact_type: 'indexeddb_full',
    source_api: 'IndexedDB full dump via content script',
    record_count: results.length,
    collected_count: collected,
    skipped_count: skipped,
    records: results,
    notes: 'Complete dump of all IndexedDB records per origin',
  };
}

/**
 * Collect signed-in Chrome account information.
 * Shows which Google account is signed into Chrome.
 */
export async function collectIdentity(onProgress) {
  const result = {
    artifact_type: 'identity',
    source_api: 'chrome.identity.getProfileUserInfo',
    profileInfo: null,
    error: null,
  };

  try {
    if (chrome.identity && chrome.identity.getProfileUserInfo) {
      const info = await chrome.identity.getProfileUserInfo({ accountStatus: 'ANY' });
      result.profileInfo = {
        email: info.email || null,
        id: info.id || null,
      };
      result.record_count = info.email ? 1 : 0;
      onProgress?.(`identity: ${info.email || 'no account signed in'}`);
    } else {
      result.error = 'chrome.identity API not available';
    }
  } catch (e) {
    result.error = e.message;
  }

  return result;
}

/**
 * Collect detailed system information.
 * CPU, memory, storage, and platform details.
 */
export async function collectSystemInfo(onProgress) {
  const result = {
    artifact_type: 'system_info',
    source_api: 'chrome.system.*',
    platform: null,
    cpu: null,
    memory: null,
    storage: null,
    error: null,
  };

  try {
    // Platform info
    if (chrome.runtime.getPlatformInfo) {
      result.platform = await chrome.runtime.getPlatformInfo();
    }

    // CPU info
    if (chrome.system?.cpu?.getInfo) {
      result.cpu = await new Promise((resolve) => {
        chrome.system.cpu.getInfo(resolve);
      });
    }

    // Memory info
    if (chrome.system?.memory?.getInfo) {
      result.memory = await new Promise((resolve) => {
        chrome.system.memory.getInfo(resolve);
      });
    }

    // Storage info
    if (chrome.system?.storage?.getInfo) {
      result.storage = await new Promise((resolve) => {
        chrome.system.storage.getInfo(resolve);
      });
    }

    result.record_count = 1;
    onProgress?.('systemInfo: collected');
  } catch (e) {
    result.error = e.message;
  }

  return result;
}

/**
 * Collect reading list items.
 * Chrome 120+ MV3 only.
 */
export async function collectReadingList(onProgress) {
  const result = {
    artifact_type: 'reading_list',
    source_api: 'chrome.readingList',
    records: [],
    error: null,
  };

  try {
    if (chrome.readingList && chrome.readingList.query) {
      const items = await chrome.readingList.query({});
      result.records = items;
      result.record_count = items.length;
      onProgress?.(`readingList: ${items.length} items`);
    } else {
      result.error = 'chrome.readingList API not available (requires Chrome 120+)';
      result.record_count = 0;
    }
  } catch (e) {
    result.error = e.message;
    result.record_count = 0;
  }

  return result;
}

/** Environment metadata describing where and how the acquisition ran. */
export function collectEnvironment() {
  const ua = navigator.userAgent;
  const chromeVersion = (ua.match(/Chrome\/([\d.]+)/) || [])[1] || 'unknown';
  const opt = Intl.DateTimeFormat().resolvedOptions();
  const m = chrome.runtime.getManifest();
  return {
    user_agent: ua,
    chrome_version: chromeVersion,
    platform: navigator.userAgentData?.platform || navigator.platform || 'unknown',
    locale: opt.locale,
    timezone: opt.timeZone,
    languages: navigator.languages || [navigator.language],
    extension_id: chrome.runtime.id,
    extension_name: m.name,
    extension_version: m.version,
  };
}
