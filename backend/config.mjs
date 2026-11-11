import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function readLocalEnv(file = new URL('.env', import.meta.url)) {
  let text;
  try { text = readFileSync(file, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return {}; throw error; }
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || match[2].startsWith('#')) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    values[match[1]] = value;
  }
  return values;
}

export function makeConfig(overrides = {}, environment = process.env) {
  const env = { ...readLocalEnv(), ...environment };
  const port = overrides.port ?? Number(env.LINK_LENS_PORT || 43187);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('LINK_LENS_PORT must be a valid port.');
  if (overrides.host && overrides.host !== '127.0.0.1') throw new Error('The backend can only bind to 127.0.0.1.');
  const base = new URL(overrides.llmBaseUrl || env.LLM_BASE_URL || 'https://api.openai.com/v1');
  const localProvider = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if (base.protocol !== 'https:' && !(base.protocol === 'http:' && localProvider)) throw new Error('The LLM endpoint requires HTTPS; local endpoints may use HTTP.');
  if (base.username || base.password || base.search || base.hash) throw new Error('The LLM endpoint URL cannot contain credentials, a query, or a fragment.');
  const model = String(overrides.llmModel ?? env.LLM_MODEL ?? '').trim().slice(0, 200);
  const apiKey = String(overrides.llmApiKey ?? env.LLM_API_KEY ?? env.OPENAI_API_KEY ?? '').trim();
  const token = String(overrides.token || randomBytes(32).toString('base64url'));
  if (token.length < 24 || token.length > 256 || /[\s\u0000-\u001f]/.test(token)) throw new Error('The local connection token must contain at least 24 non-whitespace characters.');
  return Object.freeze({
    host: '127.0.0.1', port, token,
    maxBodyBytes: 128 * 1024, maxConcurrent: 2, rateLimit: 30,
    networkTimeoutMs: 12000, llmTimeoutMs: 20000,
    ...overrides,
    host: '127.0.0.1', port, token,
    llmBaseUrl: base.href.replace(/\/$/, ''), llmModel: model, llmApiKey: apiKey,
    llmConfigured: Boolean(model && (apiKey || localProvider)),
    providerHost: base.host,
    llmTokenParameter: ['max_tokens','max_completion_tokens'].includes(overrides.llmTokenParameter || env.LLM_TOKEN_PARAMETER) ? overrides.llmTokenParameter || env.LLM_TOKEN_PARAMETER : 'max_tokens',
  });
}

export const backendDirectory = fileURLToPath(new URL('.', import.meta.url));
