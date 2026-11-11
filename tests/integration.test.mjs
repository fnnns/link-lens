import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../backend/server.mjs';
import { createController } from '../extension/controller.js';

test('extension approval flows through real local HTTP service with exact model payload and no prior model call', async t => {
  const localToken = 'integration-only-local-token-0123456789';
  const modelKey = 'integration-only-fake-model-secret';
  const extensionOrigin = 'chrome-extension://' + 'b'.repeat(32);
  const providerRequests = [];
  const app = createApp({ port: 0, token: localToken, llmBaseUrl: 'https://model.example/v1', llmModel: 'test-model', llmApiKey: modelKey }, {
    network: {
      lookup: async () => [{ address: '1.1.1.1', family: 4 }],
      requestHead: async () => ({ status: 200, headers: { 'content-type': 'text/html', 'x-content-type-options': 'nosniff' }, tls: { authorized: true, protocol: 'TLSv1.3', daysRemaining: 30 } })
    },
    llm: { fetch: async (url, options) => {
      providerRequests.push({ url, options });
      return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ summary: 'Only the supplied evidence is interpreted; this cannot prove website safety.', observations: [], unknowns: ['The operator identity is unknown.'] }) } }] }), { status: 200 });
    } }
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { app.closeAllConnections(); app.close(resolve); }));
  const backendUrl = 'http://127.0.0.1:' + app.address().port;
  const local = {}, session = {};
  const area = values => ({
    async get(keys) { if (keys === null) return structuredClone(values); return Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter(key => key in values).map(key => [key, structuredClone(values[key])])); },
    async set(data) { Object.assign(values, structuredClone(data)); },
    async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; }
  });
  const snapshot = {
    version: 1, scannedAt: '2026-11-10T13:00:00Z',
    page: { url: 'https://example.com/account', origin: 'https://example.com', hostname: 'example.com', title: 'PRIVATE_TITLE_NOT_TO_BE_SENT', protocol: 'https:', secureContext: true },
    counts: { links: 1, externalLinks: 0, forms: 0, passwordForms: 0, scripts: 0, externalScripts: 0, inlineScripts: 0, iframes: 0, httpResources: 0, downloads: 0 },
    forms: [], resources: { scriptOrigins: [], frameOrigins: [], linkOrigins: [] }, limitations: []
  };
  let id = 0;
  const browser = {
    storage: { local: area(local), session: area(session) },
    tabs: { get: async () => ({ id: 8, url: snapshot.page.url }), create: async () => {} },
    runtime: { getURL: file => extensionOrigin + '/' + file },
    scripting: { executeScript: async () => [{ result: structuredClone(snapshot) }] }
  };
  const controller = createController({ browser, randomId: () => 'integration-' + (++id), fetchImpl: (url, options) => fetch(url, { ...options, headers: { ...options.headers, Origin: extensionOrigin } }) });
  const report = await controller.openReport({ id: 8 });
  await controller.handle({ type: 'SAVE_SETTINGS', backendUrl, backendToken: localToken });
  const network = await controller.handle({ type: 'RUN_NETWORK', scanId: report.scanId });
  assert.equal(network.network.http.status, 200);
  assert.equal(providerRequests.length, 0);
  const preview = await controller.handle({ type: 'PREPARE_LLM', scanId: report.scanId, includeText: false });
  assert.equal(providerRequests.length, 0);
  assert.ok(!JSON.stringify(preview.payload).includes('PRIVATE_TITLE_NOT_TO_BE_SENT'));
  const result = await controller.handle({ type: 'RUN_LLM', scanId: report.scanId, previewId: preview.previewId });
  assert.equal(providerRequests.length, 1);
  const actual = JSON.parse(providerRequests[0].options.body);
  assert.deepEqual(JSON.parse(actual.messages[1].content).untrustedWebsiteReport, preview.payload);
  assert.equal(providerRequests[0].options.headers.Authorization, 'Bearer ' + modelKey);
  assert.match(result.llm.summary, /cannot prove/);
  assert.ok(!JSON.stringify(result).includes(modelKey));
  assert.ok(!JSON.stringify(result).includes(localToken));
});
