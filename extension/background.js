import { createController } from './controller.js';

const controller = createController({ browser: chrome });
async function restrictStorage() {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}
restrictStorage().catch(() => {});
chrome.runtime.onInstalled.addListener(() => { restrictStorage().catch(() => {}); });
chrome.action.onClicked.addListener(tab => {
  controller.openReport(tab).catch(() => { console.error('Link Lens could not create a report. Please try again.'); });
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL('report.html'))) {
    sendResponse({ ok: false, error: 'This operation can only be started from the extension report page.' }); return false;
  }
  controller.handle(message).then(data => sendResponse({ ok: true, data }), error => sendResponse({ ok: false, error: error.message || 'The operation failed. Please try again.' }));
  return true;
});
