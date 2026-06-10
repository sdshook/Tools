// © 2026, Shane Shook, All Rights Reserved - this tool is for testing and analysis.
//
// Browser Audit Inventory — background service worker
//
// Deliberately minimal. The toolbar icon opens the acquisition console in a
// full browser tab rather than a popup: the console runs a multi-step
// collection and uses the File System Access picker, and a popup would close
// the moment it loses focus (including when the OS file picker opens),
// aborting the acquisition. A tab stays open until the operator closes it.

const CONSOLE_PATH = 'src/export.html';

chrome.action.onClicked.addListener(async () => {
  const url = chrome.runtime.getURL(CONSOLE_PATH);
  const existing = await chrome.tabs.query({ url });
  if (existing.length > 0) {
    await chrome.tabs.update(existing[0].id, { active: true });
    if (existing[0].windowId != null) {
      await chrome.windows.update(existing[0].windowId, { focused: true });
    }
  } else {
    await chrome.tabs.create({ url });
  }
});
