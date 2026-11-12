# Link Lens - Website Inspector

Link Lens helps you inspect the website in your current tab and make informed browsing decisions. It brings page structure, form destinations, external resource origins, and optional network checks into one evidence-based report. An optional OpenAI-compatible LLM explains the findings, suggests next steps, and highlights what still needs verification.

Basic inspection runs locally in Chrome and Edge without an account, backend, or language model. You choose when to run network checks and what to share with a model. Reports keep observed facts, interpretations, and unknown information clearly separated.

## Installation

1. Extract the complete toolkit. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
2. Enable **Developer mode**, select **Load unpacked**, and choose the **extension** folder containing `manifest.json`.
3. Pin Link Lens in the browser toolbar. Open an HTTP or HTTPS website and click its icon.
4. Review the report in the new tab. The extension does not continuously monitor your other tabs.

This is an unpacked development extension, not a Chrome Web Store release. No dependency installation is required. Browser settings, extension pages, store pages, local files, and other protected pages cannot be inspected. Restricted pages produce an explanatory message.

## Inspection features

| Feature | Information | Additional network access |
| --- | --- | --- |
| Current page | Hostname, protocol, secure-context status, title, language, and self-declared technology metadata | None |
| Forms | Target origins, methods, password-field presence, cross-origin targets, and HTTP submission targets | None |
| Resources | Link counts, script origins, iframe origins, and declared HTTP resources | None |
| Public network inspection | DNS addresses, backend-observed TLS information, root-path HEAD responses, and selected security headers | The local backend contacts the origin after you request it |
| Optional LLM explanation | Evidence summaries, cautious interpretations, actions, and unknowns | Sent to the configured provider only after preview and confirmation |

The collector does not read form values, passwords, cookies, or website storage. It inspects the main document without reading iframe contents. Page URLs omit credentials, query parameters, and fragments. Form and resource targets retain origins only. Lists are bounded, and reports explain truncation.

Reports are held in browser session storage, with at most 12 recent reports and a two-hour retention limit. They are not synchronized to a cloud account. Browser session data is cleared when the browser session ends.

Public network inspection uses standard ports and the origin root path. It does not send browser login state, scan other ports, download page bodies, or bypass certificate validation. Results can differ from the page loaded in your browser. Timeouts, unsupported HEAD requests, and connection restrictions remain unknown.

## Local backend

Skip this section if you only need local page inspection.

1. Use Node.js 22 or later. On Windows, double-click **Start-Backend.cmd**, or run `node backend/server.mjs` from the toolkit directory. The launcher can also use an existing bundled Codex Node.js runtime.
2. The console displays the local address and a **local access token**. This token is separate from the model provider API key and changes whenever the backend restarts.
3. Open **Local backend settings** in the extension report. Enter the address, normally `http://127.0.0.1:43187`, and the token. Save and test the connection.
4. Request network inspection. Close the backend console to stop the service.

The service binds only to `127.0.0.1`. Inspection and analysis endpoints require the local token. The health endpoint does not return credentials. The service restricts request origins, host headers, body size, concurrency, and frequency. Targets must resolve exclusively to public addresses. Connections use their validated DNS results, and redirects are validated again to prevent private-network access and DNS rebinding.

## OpenAI-compatible models

Copy `backend/.env.example` to `backend/.env` and edit it locally:

```dotenv
LLM_BASE_URL=https://your-provider.example/v1
LLM_API_KEY=your-provider-api-key
LLM_MODEL=your-available-model-name
LINK_LENS_PORT=43187
```

Restart the backend and update the local access token in the extension settings. Select **Preview LLM analysis** and review the provider, model, and exact JSON before confirming. By default, the payload contains the website origin and structured inspection facts, without titles or body text. You can explicitly include a title, description, and text excerpt.

The provider key is read only by the backend. It is not embedded in the extension, included in reports, or sent to the inspected website. Packaging excludes private `.env` files. The provider must support `/chat/completions` and `response_format: {"type":"json_object"}`. Supply a model your provider supports. For models requiring `max_completion_tokens`, set `LLM_TOKEN_PARAMETER=max_completion_tokens` in `.env`. Local compatible providers can use HTTP loopback addresses.

Requests may incur charges under your provider's terms and occur only after confirmation. Missing configuration or provider errors do not invalidate local results. Automated development checks use controlled model responses; real provider calls require your own local configuration.

## Data and model boundaries

Optional excerpts exclude form fields, editable areas, scripts, and selected hidden content. Redaction attempts to remove email addresses, long numbers, and common key formats, but cannot guarantee removal of every private detail. Review the payload before sending it. Body text is excluded by default.

Page titles, text, response headers, and certificate fields are untrusted data. The backend gives the model no browser or network tools, requests evidence-based English output, and validates the returned JSON. Results are rendered as plain text. Models can still make mistakes or be influenced by hostile content, so model explanations remain separate from observed facts.

## Limitations

Reports support manual review of the evidence collected for a specific check. The current version does not calculate a validated overall safety score or certify website trustworthiness.

This version does not query WHOIS, registration dates, reputation databases, real ownership, or historical records. It is not a vulnerability scanner. HTTPS, third-party scripts, or a missing response header alone do not prove that a website is trustworthy or malicious.

## Development

```text
node --test
node scripts/package.mjs
```

Tests cover collection privacy, preview approval, destination binding, token and origin restrictions, DNS validation and redirects, timeouts, response validation, and a local HTTP integration flow with a simulated provider.

For an interface demonstration, run `node scripts/preview.mjs` and open the printed URL. Demo mode is clearly labeled and disables actual scans, settings changes, network inspection, and model requests.

All source, comments, interface text, examples, and documentation must be in English. Text files use ASCII source characters. Tests specifically exercising Unicode handling represent those characters with ASCII Unicode escapes. The English-only regression check runs with the normal test suite.

## Official references

- [Chrome activeTab permission](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab)
- [Chrome scripting API](https://developer.chrome.com/docs/extensions/reference/api/scripting)
- [Extension network requests](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests)
- [OpenAI Chat Completions API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)
