import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { collectPage } from '../extension/collector.js';
import { analyzeSnapshot } from '../extension/analyzer.js';

function node(tagName, attrs = {}) {
  return {
    tagName: tagName.toUpperCase(),
    getAttribute(name) { if (name === 'value') throw new Error('Must not read field values'); return attrs[name] ?? null; },
    hasAttribute(name) { return Object.hasOwn(attrs, name); },
    get value() { throw new Error('Must not read field values'); }
  };
}
function fixture({ url = 'https://user:credential-secret@example.com/account?token=query-secret#fragment-secret', forms = [], scripts = [], frames = [], links = [], resources = [], body } = {}) {
  const selectors = new Map([
    ['a[href]', links], ['form', forms], ['script', scripts], ['script[src]', scripts.filter(item => item.hasAttribute('src'))], ['iframe', frames],
    ['script[src], link[rel="stylesheet"][href], link[rel="preload"][href], img[src], iframe[src], video[src], audio[src], source[src], object[data], embed[src]', resources]
  ]);
  return {
    URL, Date,
    location: { href: url },
    window: { isSecureContext: url.startsWith('https:'), get localStorage() { throw new Error('Must not read storage'); } },
    document: {
      title: 'Example page', documentElement: { lang: 'en' },
      querySelectorAll(selector) { if (!selectors.has(selector)) throw new Error('Unexpected selector: ' + selector); return selectors.get(selector); },
      querySelector() { return null; },
      get cookie() { throw new Error('Must not read cookies'); },
      get body() { if (!body) throw new Error('Body text accessed without explicit request'); return body; }
    }
  };
}
function collect(context, includeText = false) { return JSON.parse(vm.runInNewContext(`JSON.stringify((${collectPage.toString()})(${includeText}))`, context)); }
function safeSnapshot() { return collect(fixture({ url: 'https://example.com/' })); }
const ids = report => report.findings.map(item => item.id);

test('collector serializes without outer dependencies and removes URL credentials/query/fragment', () => {
  const snapshot = collect(fixture());
  assert.equal(snapshot.page.url, 'https://example.com/account');
  assert.equal(snapshot.page.origin, 'https://example.com');
  assert.equal(snapshot.page.hasCredentials, true);
  assert.equal(snapshot.page.queryParameterCount, 1);
  assert.ok(!Object.hasOwn(snapshot, 'excerpt'));
  const serialized = JSON.stringify(snapshot);
  for (const secret of ['credential-secret', 'query-secret', 'fragment-secret']) assert.ok(!serialized.includes(secret));
});

test('collector reads field types only and records actual form origin, not values', () => {
  const form = node('form', { action: 'http://submit.example.net/post?secret=hidden', method: 'post' });
  form.elements = [node('input', { type: 'password', value: 'never-read' }), node('input', { type: 'email' })];
  const snapshot = collect(fixture({ url: 'https://example.com/login', forms: [form] }));
  assert.equal(snapshot.counts.passwordForms, 1);
  assert.deepEqual(snapshot.forms[0], { actionOrigin: 'http://submit.example.net', method: 'POST', hasPassword: true, fieldTypes: ['password', 'email'], fieldCount: 2, crossOrigin: true, insecureAction: true });
  assert.ok(!JSON.stringify(snapshot).includes('never-read'));
  assert.ok(!JSON.stringify(snapshot).includes('secret=hidden'));
  assert.ok(ids(analyzeSnapshot(snapshot)).includes('password-to-http'));
});

test('resource detail keeps origins only and distinguishes declared HTTP resources', () => {
  const script = node('script', { src: 'https://cdn.example.net/app.js?key=private-query' });
  const image = node('img', { src: 'http://images.example.net/a.png?key=private-query' });
  const frame = node('iframe', { src: 'https://frames.example.net/private-path?token=private-query' });
  const snapshot = collect(fixture({ url: 'https://example.com/', scripts: [script], frames: [frame], resources: [script, image, frame] }));
  assert.deepEqual(snapshot.resources.scriptOrigins, ['https://cdn.example.net']);
  assert.deepEqual(snapshot.resources.frameOrigins, ['https://frames.example.net']);
  assert.equal(snapshot.counts.httpResources, 1);
  assert.ok(!JSON.stringify(snapshot).includes('private-query'));
  const result = analyzeSnapshot(snapshot);
  assert.ok(ids(result).includes('http-resources'));
  assert.ok(ids(result).includes('third-party-scripts'));
});

test('optional excerpt removes fields before reading text and redacts common sensitive strings', () => {
  let removed = false;
  const body = { cloneNode() { return {
    querySelectorAll(selector) { assert.ok(selector.includes('textarea')); assert.ok(selector.includes('[contenteditable]')); return [{ remove() { removed = true; } }]; },
    get textContent() { assert.ok(removed, 'Fields must be removed before reading text'); return 'Contact alice@example.com +86 13800138000 token=abcdefghijklmnop sk-abcdefghijklmnopqrstuvwxyz123456 Normal content'; }
  }; } };
  const snapshot = collect(fixture({ body }), true);
  assert.ok(snapshot.excerpt.includes('Normal content'));
  for (const privatePart of ['alice@example.com', '13800138000', 'abcdefghijklmnop', 'sk-abcdefghijklmnopqrstuvwxyz']) assert.ok(!snapshot.excerpt.includes(privatePart));
  assert.ok(snapshot.limitations.some(text => text.includes('may still contain')));
});

test('origin and form lists are bounded while observed counts remain complete', () => {
  const scripts = Array.from({ length: 70 }, (_, index) => node('script', { src: `https://cdn${index}.example.net/a.js` }));
  const forms = Array.from({ length: 105 }, () => { const form = node('form'); form.elements = [node('input', { type: 'password' })]; return form; });
  const snapshot = collect(fixture({ scripts, forms }));
  assert.equal(snapshot.resources.scriptOrigins.length, 64);
  assert.equal(snapshot.forms.length, 100);
  assert.equal(snapshot.counts.forms, 105);
  assert.equal(snapshot.counts.passwordForms, 105);
  assert.ok(snapshot.limitations.some(text => text.includes('truncation')));
});

test('normal HTTPS snapshot does not invent certificate, reputation, or server headers', () => {
  const result = analyzeSnapshot(safeSnapshot());
  assert.equal(result.summary.level, 'no-obvious-issues');
  assert.deepEqual(result.findings, []);
  for (const forbidden of ['valid certificate', 'website is safe', 'no malware', 'registration date']) assert.ok(!JSON.stringify(result).includes(forbidden));
});

test('cross-origin password form is review evidence, not an automatic phishing verdict', () => {
  const snapshot = safeSnapshot();
  snapshot.forms = [{ hasPassword: true, insecureAction: false, crossOrigin: true, actionOrigin: 'https://login.example.net' }];
  const result = analyzeSnapshot(snapshot);
  assert.equal(result.summary.level, 'review');
  assert.equal(result.findings[0].severity, 'medium');
  assert.ok(result.findings[0].evidence.includes('legitimate'));
});

test('HTTP password page is prioritized while IDN alone remains informational', () => {
  const insecure = safeSnapshot(); insecure.page.url = 'http://example.com/login'; insecure.counts.passwordForms = 1;
  assert.equal(analyzeSnapshot(insecure).summary.level, 'attention');
  const idn = safeSnapshot(); idn.page.url = 'https://xn--r8jz45g.jp/';
  const result = analyzeSnapshot(idn);
  assert.ok(ids(result).includes('idn-domain'));
  assert.equal(result.summary.level, 'no-obvious-issues');
});

test('unsupported or malformed snapshot fails clearly', () => {
  assert.throws(() => analyzeSnapshot(null), /snapshot format/);
  const snapshot = safeSnapshot(); snapshot.page.url = 'chrome://settings';
  assert.throws(() => analyzeSnapshot(snapshot), /HTTP and HTTPS/);
});
