import test from 'node:test';
import assert from 'node:assert/strict';
import { createController, validateBackendUrl, buildLlmPayload } from '../extension/controller.js';
import { analyzeSnapshot } from '../extension/analyzer.js';

const snapshot = {
  version: 1, scannedAt: '2026-11-10T13:00:00Z',
  page: { origin: 'https://example.com', url: 'https://example.com/account', hostname: 'example.com', title: 'Private account title', description: 'Private description', protocol: 'https:', secureContext: true },
  counts: { forms: 1, links: 4 },
  forms: [{ actionOrigin: 'https://example.com', method: 'POST', hasPassword: true, fieldTypes: ['password'], fieldCount: 1, crossOrigin: false, insecureAction: false }],
  resources: { scriptOrigins: [], frameOrigins: [], linkOrigins: [] }, limitations: [], excerpt: 'Private page text'
};
function harness({ onSessionSet } = {}) {
  const local = {}, session = {}, requests = [], opened = [];
  const tab = { id: 12, url: 'https://example.com/account?session=secret#token' };
  const storage = object => ({
    async get(keys) { if (keys === null) return structuredClone(object); const names = Array.isArray(keys) ? keys : [keys]; return Object.fromEntries(names.filter(key => key in object).map(key => [key, structuredClone(object[key])])); },
    async set(values) { Object.assign(object, structuredClone(values)); if (object === session && onSessionSet) await onSessionSet(values, { local, session }); },
    async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete object[key]; }
  });
  const browser = {
    storage: { local: storage(local), session: storage(session) },
    tabs: { async get() { return structuredClone(tab); }, async create(data) { opened.push(data); } },
    scripting: { async executeScript(options) { const result = structuredClone(snapshot); if (!options.args[0]) delete result.excerpt; return [{ result }]; } },
    runtime: { getURL: name => 'chrome-extension://' + 'a'.repeat(32) + '/' + name }
  };
  let tick = 1000000, id = 0, health = { ok: true, llm: { configured: true, providerHost: 'api.example.test', model: 'configured-test-model', configurationId: 'process-one' } };
  const fetchImpl = async (url, options) => {
    requests.push({ url, ...options });
    const data = url.endsWith('/health') ? health : url.endsWith('/analyze') ? { summary: 'Test model response', observations: [], unknowns: [], provider: 'api.example.test', model: 'configured-test-model' } : { origin: snapshot.page.origin, dns: [], limitations: [] };
    return new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  const controller = createController({ browser, fetchImpl, now: () => tick, randomId: () => 'test-id-' + (++id) });
  return { controller, local, session, tab, requests, opened, advance(ms) { tick += ms; }, setHealth(next) { health = next; } };
}

test('backend configuration can only target loopback without URL credentials or paths', () => {
  assert.equal(validateBackendUrl('http://localhost:43187'), 'http://localhost:43187');
  assert.equal(validateBackendUrl('http://127.1:43187'), 'http://127.0.0.1:43187');
  for (const url of ['https://example.com', 'http://127.0.0.1.evil.test', 'http://user:secret@localhost:43187', 'http://localhost:43187/steal', 'http://localhost:43187/?token=secret']) {
    assert.throws(() => validateBackendUrl(url), undefined, url);
  }
});
test('toolbar capture stays session-only and opens a report with no source secrets in URL', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  assert.equal(report.snapshot.page.origin, 'https://example.com');
  assert.deepEqual(h.local, {}); assert.equal(h.requests.length, 0);
  assert.ok(!JSON.stringify(h.opened).includes('session=secret'));
  assert.equal(Object.keys(h.session).length, 1);
  assert.ok(!('sourceTabId' in report)); assert.ok(!('preview' in report));
});
test('default cloud payload excludes page text and browser internals', () => {
  const payload = buildLlmPayload({ snapshot, analysis: { findings: [] }, network: null });
  assert.equal(payload.origin, snapshot.page.origin); assert.ok(!('page' in payload));
  const json = JSON.stringify(payload);
  assert.ok(!json.includes('Private')); assert.ok(!json.includes('session=secret'));
  assert.equal(buildLlmPayload({ snapshot, analysis: { findings: [] } }, true).page.excerpt, 'Private page text');
});
test('default evidence does not upload secret canonical URL path segments', () => {
  const source = structuredClone(snapshot); source.page.canonical = 'https://other.test/account/private-reset-path-token';
  const payload = buildLlmPayload({ snapshot: source, analysis: analyzeSnapshot(source) });
  assert.ok(JSON.stringify(payload).includes('https://other.test'));
  assert.ok(!JSON.stringify(payload).includes('private-reset-path-token'));
});
test('LLM sends only the exact approved preview; preview cannot be replayed', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  await h.controller.handle({ type: 'SAVE_SETTINGS', backendUrl: 'http://127.0.0.1:43187', backendToken: 'test-only-local-access-token-not-secret' });
  const preview = await h.controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId, includeText: false });
  assert.equal(h.requests.filter(r => r.url.endsWith('/analyze')).length, 0);
  await h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId, payload: { origin: 'https://attacker.test' } });
  const sent = h.requests.find(r => r.url.endsWith('/analyze'));
  assert.deepEqual(JSON.parse(sent.body), { report: preview.payload });
  assert.equal(sent.credentials, 'omit'); assert.ok(sent.headers.Authorization.startsWith('Bearer '));
  await assert.rejects(() => h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId }), /preview/);
});
test('settings changed while consuming a preview cannot redirect the approved request', async () => {
  let armed = false, changed = false;
  const oldBackend = 'http://127.0.0.1:43187';
  const oldToken = 'original-test-only-local-access-token';
  const newBackend = 'http://localhost:43222';
  const newToken = 'replacement-test-only-local-access-token';
  const h = harness({ onSessionSet(values, { local }) {
    if (armed && !changed && Object.values(values).some(value => value?.scanId && value.preview === null)) {
      // Simulate another report tab updating shared settings after health was
      // validated, precisely while this report consumes its one-use approval.
      changed = true;
      local.backendUrl = newBackend;
      local.backendToken = newToken;
    }
  } });
  const report = await h.controller.openReport(h.tab);
  await h.controller.handle({ type: 'SAVE_SETTINGS', backendUrl: oldBackend, backendToken: oldToken });
  const preview = await h.controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId });
  armed = true;
  await h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId });
  assert.equal(changed, true);
  assert.equal(h.local.backendUrl, newBackend);
  const sent = h.requests.find(request => request.url.endsWith('/analyze'));
  assert.equal(sent.url, oldBackend + '/analyze');
  assert.equal(sent.headers.Authorization, 'Bearer ' + oldToken);
  assert.deepEqual(JSON.parse(sent.body), { report: preview.payload });
  assert.ok(!h.requests.some(request => request.url.startsWith(newBackend)));
});

test('changing provider after preview blocks model transmission', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  await h.controller.handle({ type: 'SAVE_SETTINGS', backendUrl: 'http://127.0.0.1:43187', backendToken: 'test-only-local-access-token-not-secret' });
  const preview = await h.controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId });
  h.setHealth({ ok: true, llm: { configured: true, providerHost: 'changed.example.test', model: 'configured-test-model' } });
  await assert.rejects(() => h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId }), /changed/);
  assert.equal(h.requests.filter(r => r.url.endsWith('/analyze')).length, 0);
});
test('rescan cannot read a different site after the source tab navigates', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  h.tab.url = 'https://other.test/';
  await assert.rejects(() => h.controller.handle({ type: 'REFRESH_SCAN', scanId: report.scanId }), /another website/);
});
test('backend restart with unchanged provider and model still invalidates approval', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  const preview = await h.controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId });
  h.setHealth({ ok: true, llm: { configured: true, providerHost: 'api.example.test', model: 'configured-test-model', configurationId: 'process-two' } });
  await assert.rejects(() => h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId }), /changed/);
  assert.equal(h.requests.filter(r => r.url.endsWith('/analyze')).length, 0);
});
test('editing local backend settings consumes any pending approvals', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  const preview = await h.controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId });
  await h.controller.handle({ type: 'SAVE_SETTINGS', backendUrl: 'http://localhost:43187', backendToken: 'new-test-only-local-access-token' });
  await assert.rejects(() => h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId }), /preview/);
  assert.equal(h.requests.filter(r => r.url.endsWith('/analyze')).length, 0);
});
test('expired preview and reports cannot silently submit stale data', async () => {
  const h = harness(); const report = await h.controller.openReport(h.tab);
  const preview = await h.controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId });
  h.advance(6 * 60 * 1000);
  await assert.rejects(() => h.controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId }), /preview/);
  h.advance(2 * 60 * 60 * 1000);
  await assert.rejects(() => h.controller.handle({ type: 'GET_REPORT', scanId: report.scanId }), /expired/);
});
test('restricted browser pages produce a helpful error report instead of a blank UI', async () => {
  const h = harness(); h.tab.url = 'chrome://settings/';
  const report = await h.controller.openReport(h.tab);
  assert.match(report.error, /cannot be scanned/); assert.equal(h.opened.length, 1); assert.equal(h.requests.length, 0);
});
