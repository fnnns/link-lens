import { collectPage } from './collector.js';
import { analyzeSnapshot } from './analyzer.js';
import { sanitizeReport } from './payload.js';

const DEFAULT_BACKEND = 'http://127.0.0.1:43187';
const PREFIX = 'report:';
const MAX_AGE = 2 * 60 * 60 * 1000;

export function validateBackendUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error('Enter a local backend address, such as http://127.0.0.1:43187.'); }
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('The backend address must use local http://127.0.0.1 or http://localhost, without a path or remote server.');
  }
  return url.origin;
}

export function buildLlmPayload(report, includeText = false) {
  const snapshot = report.snapshot;
  const result = {
    origin: snapshot.page.origin,
    counts: snapshot.counts,
    forms: snapshot.forms,
    resources: snapshot.resources,
    localFindings: report.analysis.findings,
    network: report.network || undefined
  };
  if (includeText) result.page = {
    title: snapshot.page.title,
    description: snapshot.page.description,
    excerpt: snapshot.excerpt || ''
  };
  return sanitizeReport(result);
}

export function createController({ browser, fetchImpl = fetch, now = () => Date.now(), randomId = () => crypto.randomUUID() }) {
  const locks = new Set();
  const publicReport = report => {
    const { sourceTabId, sourceOrigin, preview, createdAt, revision, ...safe } = report;
    return safe;
  };
  async function settings() {
    const stored = await browser.storage.local.get(['backendUrl', 'backendToken']);
    return { backendUrl: stored.backendUrl || DEFAULT_BACKEND, backendToken: stored.backendToken || '' };
  }
  async function loadReport(scanId) {
    if (!/^[a-zA-Z0-9-]{8,80}$/.test(scanId || '')) throw new Error('The report ID is invalid. Click the extension icon on the website you want to inspect.');
    const key = PREFIX + scanId;
    const report = (await browser.storage.session.get(key))[key];
    if (!report || now() - report.createdAt > MAX_AGE) throw new Error('This report has expired. Return to the website and click the extension icon again.');
    return report;
  }
  async function saveReport(report) {
    await browser.storage.session.set({ [PREFIX + report.scanId]: report });
  }
  async function invalidatePreviews() {
    const records = await browser.storage.session.get(null);
    for (const [key, report] of Object.entries(records)) {
      if (key.startsWith(PREFIX) && report.preview) { report.preview = null; await browser.storage.session.set({ [key]: report }); }
    }
  }
  async function capture(tabId, sourceOrigin, includeText = false) {
    const tab = await browser.tabs.get(tabId);
    if (!tab.url || !/^https?:\/\//i.test(tab.url)) throw new Error('Browser settings pages, extension pages, and local files cannot be scanned. Open a regular HTTP or HTTPS website and click the extension icon.');
    if (sourceOrigin && new URL(tab.url).origin !== sourceOrigin) throw new Error('The source tab has navigated to another website. Click the extension icon on the new website.');
    let results;
    try {
      results = await browser.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: collectPage, args: [includeText] });
    } catch {
      throw new Error('The browser did not allow access to this page. Return to the page, wait for it to finish loading, and click the extension icon again.');
    }
    const snapshot = results?.[0]?.result;
    if (!snapshot?.page?.origin) throw new Error('Page information could not be read. Try inspecting the page again.');
    const after = await browser.tabs.get(tabId);
    if (!after.url || new URL(after.url).origin !== snapshot.page.origin || (sourceOrigin && snapshot.page.origin !== sourceOrigin)) {
      throw new Error('The page navigated during inspection. Click the extension icon on the current page again.');
    }
    return snapshot;
  }
  async function callBackend(route, body, boundConfig) {
    const config = boundConfig || await settings();
    const base = validateBackendUrl(config.backendUrl);
    if (route !== '/health' && !config.backendToken) throw new Error('First enter the access token shown when the backend starts in Local Backend Settings.');
    let response;
    try {
      response = await fetchImpl(base + route, {
        method: body ? 'POST' : 'GET',
        headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(config.backendToken ? { Authorization: 'Bearer ' + config.backendToken } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        credentials: 'omit', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(25000)
      });
    } catch {
      throw new Error('The local backend connection failed or timed out. Confirm that it is running and that the address and port are correct.');
    }
    const text = await response.text();
    if (text.length > 262144) throw new Error('The backend response is too large. Reading was stopped.');
    let result;
    try { result = JSON.parse(text); } catch { throw new Error('The backend did not return valid JSON. Check that the address points to the Link Lens backend.'); }
    if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error.slice(0, 300) : `The backend request failed (${response.status}).`);
    return result;
  }
  async function openReport(tab) {
    const scanId = randomId();
    const report = { scanId, createdAt: now(), revision: 1, sourceTabId: tab.id, sourceOrigin: null, network: null, llm: null };
    try {
      report.snapshot = await capture(tab.id);
      report.sourceOrigin = report.snapshot.page.origin;
      report.analysis = analyzeSnapshot(report.snapshot);
    } catch (error) { report.error = error.message; }
    const all = await browser.storage.session.get(null);
    const records = Object.entries(all).filter(([key]) => key.startsWith(PREFIX)).sort((a, b) => a[1].createdAt - b[1].createdAt);
    const stale = records.filter(([, item], index) => now() - item.createdAt > MAX_AGE || index < records.length - 11).map(([key]) => key);
    if (stale.length) await browser.storage.session.remove(stale);
    await saveReport(report);
    await browser.tabs.create({ url: browser.runtime.getURL('report.html') + '?scan=' + encodeURIComponent(scanId) });
    return publicReport(report);
  }
  async function handle(message) {
    const { type, scanId } = message || {};
    if (type === 'GET_SETTINGS') {
      const config = await settings();
      return { backendUrl: config.backendUrl, tokenSaved: Boolean(config.backendToken) };
    }
    if (type === 'SAVE_SETTINGS') {
      const backendUrl = validateBackendUrl(message.backendUrl || DEFAULT_BACKEND);
      const prior = await settings();
      const token = String(message.backendToken || '').trim();
      if (token.length > 512 || /[\r\n]/.test(token)) throw new Error('The access token format is invalid.');
      const backendToken = token || (backendUrl === prior.backendUrl ? prior.backendToken : '');
      await browser.storage.local.set({ backendUrl, backendToken });
      await invalidatePreviews();
      return { backendUrl, tokenSaved: Boolean(backendToken) };
    }
    if (type === 'CLEAR_TOKEN') { await browser.storage.local.remove('backendToken'); await invalidatePreviews(); return { cleared: true }; }
    if (type === 'CHECK_BACKEND') return callBackend('/health');
    const supported = ['GET_REPORT', 'REFRESH_SCAN', 'RUN_NETWORK', 'PREPARE_LLM', 'RUN_LLM'];
    if (!supported.includes(type)) throw new Error('This operation is not supported.');
    if (type === 'GET_REPORT') return publicReport(await loadReport(scanId));
    if (locks.has(scanId)) throw new Error('This report is already processing a request. Wait for it to finish.');
    locks.add(scanId);
    try {
      const report = await loadReport(scanId);
      if (report.error) throw new Error(report.error);
      if (type === 'REFRESH_SCAN') {
        report.snapshot = await capture(report.sourceTabId, report.sourceOrigin);
        report.analysis = analyzeSnapshot(report.snapshot);
        report.llm = null; report.preview = null; report.revision++;
      }
      if (type === 'RUN_NETWORK') {
        report.network = await callBackend('/inspect', { origin: report.snapshot.page.origin });
        report.llm = null; report.preview = null; report.revision++;
      }
      if (type === 'PREPARE_LLM') {
        const config = await settings();
        const health = await callBackend('/health', undefined, config);
        if (!health.llm?.configured) throw new Error('No model is configured in the backend. Set LLM_BASE_URL, LLM_MODEL, and any required LLM_API_KEY in backend/.env, then restart the backend.');
        if (message.includeText === true) {
          report.snapshot = await capture(report.sourceTabId, report.sourceOrigin, true);
          report.analysis = analyzeSnapshot(report.snapshot);
          report.llm = null; report.revision++;
        }
        const payload = buildLlmPayload(report, message.includeText === true);
        report.preview = { previewId: randomId(), payload, revision: report.revision, createdAt: now(), providerHost: health.llm.providerHost, model: health.llm.model, configurationId: health.llm.configurationId, backendUrl: config.backendUrl };
        await saveReport(report);
        return { previewId: report.preview.previewId, payload, providerHost: health.llm.providerHost, model: health.llm.model };
      }
      if (type === 'RUN_LLM') {
        const preview = report.preview;
        if (!preview || preview.previewId !== message.previewId || preview.revision !== report.revision || now() - preview.createdAt > 5 * 60 * 1000) {
          throw new Error('The send preview has expired. Create a new preview before confirming.');
        }
        const config = await settings();
        const health = await callBackend('/health', undefined, config);
        if (health.llm?.providerHost !== preview.providerHost || health.llm?.model !== preview.model || health.llm?.configurationId !== preview.configurationId || config.backendUrl !== preview.backendUrl) {
          report.preview = null; await saveReport(report);
          throw new Error('The backend model or service address has changed. Preview the content again before sending.');
        }
        report.preview = null;
        await saveReport(report);
        report.llm = await callBackend('/analyze', { report: preview.payload }, config);
      }
      await saveReport(report);
      return publicReport(report);
    } finally { locks.delete(scanId); }
  }
  return { openReport, handle };
}
