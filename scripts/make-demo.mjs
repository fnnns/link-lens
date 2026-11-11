import { writeFile } from 'node:fs/promises';
import { analyzeSnapshot } from '../extension/analyzer.js';

const snapshot = {
  version: 1, scannedAt: '2026-11-10T13:00:00.000Z',
  page: { url: 'https://portal.example/account', origin: 'https://portal.example', hostname: 'portal.example', title: 'Demo Workspace - Account Center', protocol: 'https:', lang: 'en-US', description: 'Simulated page used only to demonstrate the report layout.', secureContext: true, canonical: 'https://portal.example/account', generator: 'Example Portal (self-declared)', hasCredentials: false, queryParameterCount: 2 },
  counts: { links: 72, externalLinks: 14, forms: 3, passwordForms: 1, scripts: 20, externalScripts: 17, inlineScripts: 3, externalScriptsWithoutIntegrity: 4, iframes: 2, httpResources: 0, downloads: 4 },
  forms: [
    { actionOrigin: 'https://portal.example', method: 'POST', hasPassword: true, fieldTypes: ['email', 'password', 'submit'], fieldCount: 3, crossOrigin: false, insecureAction: false },
    { actionOrigin: 'https://portal.example', method: 'GET', hasPassword: false, fieldTypes: ['search', 'submit'], fieldCount: 2, crossOrigin: false, insecureAction: false },
    { actionOrigin: 'https://identity.example', method: 'POST', hasPassword: false, fieldTypes: ['hidden', 'submit'], fieldCount: 2, crossOrigin: true, insecureAction: false }
  ],
  resources: { scriptOrigins: ['https://portal.example', 'https://static.example', 'https://metrics.example'], frameOrigins: ['https://help.example'], linkOrigins: ['https://portal.example', 'https://identity.example', 'https://docs.example'] },
  limitations: ['This is demo data. portal.example was not scanned.', 'Only a main-page DOM snapshot is represented; cross-origin iframe contents and closed Shadow DOM are not checked.', 'No form values, cookies, or website storage were read.', 'Titles and technology identifiers are self-declared and do not verify the actual operator.']
};
const network = {
  origin: snapshot.page.origin, checkedAt: snapshot.scannedAt, dns: [{ address: '198.51.100.24', family: 4 }],
  http: { status: 200, finalOrigin: snapshot.page.origin, redirects: [], headers: { 'content-type': 'text/html; charset=utf-8', 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'content-security-policy': "default-src 'self'; script-src 'self' https://static.example", 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin' } },
  tls: { authorized: true, protocol: 'TLSv1.3', issuer: 'Simulated CA (not measured)', subject: 'CN=portal.example (demo)', validFrom: '2026-10-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z', daysRemaining: 51 },
  findings: [], limitations: ['These DNS, certificate, and response header values are demo data, not real website query results.', 'Live mode checks the root path with an unauthenticated HEAD request; results may differ from the browser page.']
};
const report = { scanId: 'demo', snapshot, analysis: analyzeSnapshot(snapshot), network, llm: null, demo: true };
await writeFile(new URL('../extension/demo-data.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
console.log('Built clearly labelled demonstration report.');
