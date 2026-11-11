const $ = id => document.getElementById(id);
const params = new URLSearchParams(location.search);
const isDemo = params.get('demo') === '1';
const scanId = params.get('scan') || '';
const settingsOnly = params.get('settings') === '1';
const state = { report: null, busy: false, preview: null, settings: { backendUrl: 'http://127.0.0.1:43187', tokenSaved: false } };
const severityLabels = { high: 'Priority review', medium: 'Review needed', info: 'Observation' };
const headerNames = ['content-type', 'strict-transport-security', 'content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'cross-origin-embedder-policy', 'server', 'x-powered-by'];
const number = value => Number.isFinite(value) ? String(value) : '-';
const text = value => value === null || value === undefined || value === '' ? 'Not observed' : String(value);
const date = value => { try { const parsed = new Date(value); return Number.isNaN(parsed.valueOf()) ? 'Time unknown' : new Intl.DateTimeFormat('en-US', { year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', hour12:false }).format(parsed); } catch { return 'Time unknown'; } };
function node(tag, className = '', content) { const item = document.createElement(tag); if (className) item.className = className; if (content !== undefined) item.textContent = String(content); return item; }
function message(type, extra = {}) {
  if (isDemo) return Promise.reject(new Error('Demo mode does not scan websites or send network or model requests.'));
  if (!globalThis.chrome?.runtime?.sendMessage) return Promise.reject(new Error('Open this report from the browser extension. The web preview only displays demo data.'));
  return chrome.runtime.sendMessage({type, scanId, ...extra}).then(result => {
    if (!result?.ok) throw new Error(result?.error || 'The extension did not return a valid result. Reopen the report.');
    return result.data;
  });
}
function showError(error) {
  const content = error?.message || String(error);
  $('error-banner').textContent = content; $('error-banner').hidden = false;
  $('error-banner').scrollIntoView({block:'start',behavior:'smooth'});
}
function success(messageText) { $('success-banner').textContent = messageText; $('success-banner').hidden = false; }
function controls() {
  const hasSnapshot = Boolean(state.report?.snapshot && !state.report.error);
  for (const button of document.querySelectorAll('[data-action]')) button.disabled = state.busy;
  for (const id of ['refresh-button','network-button','preview-button']) $(id).disabled = state.busy || isDemo || !hasSnapshot;
  $('export-button').disabled = state.busy || !hasSnapshot;
  $('preview-confirm').disabled = state.busy || isDemo || !state.preview;
  for (const id of ['save-settings-button','check-backend-button','clear-token-button']) $(id).disabled = state.busy || isDemo;
  for (const id of ['backend-url','backend-token']) $(id).disabled = state.busy || isDemo;
  $('include-text').disabled = state.busy || isDemo || !hasSnapshot;
  $('dialog-close').disabled = state.busy; $('preview-cancel').disabled = state.busy;
  $('report-main').setAttribute('aria-busy', String(state.busy));
}
async function perform(label, action) {
  if (state.busy) return;
  state.busy = true; $('error-banner').hidden = true; $('success-banner').hidden = true;
  $('busy-label').textContent = label; $('busy-label').hidden = false; controls();
  try { await action(); }
  catch (error) { showError(error); }
  finally { state.busy = false; $('busy-label').hidden = true; controls(); }
}
function factList(element, entries) {
  element.replaceChildren(...entries.map(([label, value, normalFont = false]) => {
    const row = node('div', 'fact-row'); row.append(node('dt', '', label), node('dd', normalFont ? 'normal-font' : '', text(value))); return row;
  }));
}
function findingElement(finding, expanded = false) {
  const level = ['high','medium','info'].includes(finding.severity) ? finding.severity : 'info';
  const item = node('details', `finding ${level}`); item.open = expanded;
  const heading = node('summary'); const dot = node('span','finding-dot'); dot.setAttribute('aria-hidden','true');
  heading.append(dot, node('span','',finding.title || 'Observation'), node('span','severity-label',severityLabels[level]));
  const detail = node('div','finding-detail');
  const evidence = node('p'); evidence.append(node('b','','Evidence'), document.createTextNode(text(finding.evidence)));
  const action = node('p'); action.append(node('b','','Suggested next step'), document.createTextNode(text(finding.recommendation)));
  detail.append(evidence,action); item.append(heading,detail); return item;
}
function renderLocal(report) {
  const snapshot = report.snapshot, page = snapshot.page, counts = snapshot.counts || {}, analysis = report.analysis || {};
  $('site-host').textContent = page.hostname || page.origin || 'Current website';
  $('site-title').textContent = page.title || 'No page title provided';
  $('site-url').textContent = page.url || '';
  $('protocol-badge').textContent = String(page.protocol || '').replace(':','').toUpperCase() || 'Unknown';
  $('protocol-badge').className = `protocol-badge${page.protocol === 'http:' ? ' http' : ''}`;
  $('scan-time').textContent = `Checked at ${date(snapshot.scannedAt)}`;
  const level = analysis.summary?.level;
  $('summary-banner').className = `summary-banner ${level === 'attention' ? 'attention' : level === 'review' ? 'review' : ''}`;
  $('summary-icon').textContent = level === 'attention' ? '!' : level === 'review' ? '?' : 'OK';
  $('summary-headline').textContent = analysis.summary?.headline || 'Page information loaded';
  const findings = Array.isArray(analysis.findings) ? analysis.findings : [];
  const important = findings.filter(finding => ['high','medium'].includes(finding.severity)).length;
  $('summary-count').textContent = `${important} to review / ${findings.length} observations`;
  $('metric-links').textContent = number(counts.links); $('metric-external-links').textContent = `${number(counts.externalLinks)} cross-origin links`;
  $('metric-forms').textContent = number(counts.forms); $('metric-passwords').textContent = `${number(counts.passwordForms)} with password fields`;
  $('metric-scripts').textContent = number(counts.scripts); $('metric-script-origins').textContent = `${number(counts.externalScripts)} script references with src`;
  $('metric-frames').textContent = number(counts.iframes);
  $('local-finding-count').textContent = `${findings.length} items`;
  if (findings.length) $('local-findings').replaceChildren(...findings.map((finding,index) => findingElement(finding,index === 0 || finding.severity === 'high')));
  else { const empty = node('p','empty-copy'); empty.append(node('strong','','No obvious structural issues found within the checked scope'), document.createTextNode('This is not a security certification. Connection details, server configuration, and the actual operator still require separate verification.')); $('local-findings').replaceChildren(empty); }
  factList($('page-facts'), [
    ['Website origin', page.origin], ['Page language', page.lang], ['Secure context', page.secureContext === true ? 'Yes, as reported by the browser (not a certificate check)' : page.secureContext === false ? 'No, as reported by the browser' : 'Unknown', true],
    ['Canonical URL', page.canonical || 'Not declared by the page'], ['Declared technology', page.generator || 'Not declared by the page', true], ['Page description', page.description || 'Not declared by the page', true], ['HTTP resource references', `${number(counts.httpResources)} (actual loading not confirmed)`,true]
  ]);
  const forms = Array.isArray(snapshot.forms) ? snapshot.forms : [];
  if (!forms.length) $('forms-list').replaceChildren(node('p','empty-copy','No form elements were listed in the main page. Script-based inputs and forms inside cross-origin iframes are outside this count.'));
  else {
    const rows = forms.slice(0,12).map((form,index) => {
      const row = node('div','form-item'), title = node('p','form-title');
      title.append(node('span','',`Form ${index+1}`), node('span','method-tag',form.method || 'Unknown method'));
      if (form.hasPassword) title.append(node('span','password-tag','Password fields'));
      const meta = [`${number(form.fieldCount)} fields`, form.crossOrigin ? 'Cross-origin submission' : 'Same-origin or destination unconfirmed'];
      if (form.insecureAction) meta.push('HTTP destination');
      if (Array.isArray(form.fieldTypes) && form.fieldTypes.length) meta.push(`Field types: ${form.fieldTypes.join(' / ')}`);
      row.append(title,node('p','form-origin',form.actionOrigin || 'No resolved HTTP(S) submission destination'),node('p','form-meta',meta.join(' | '))); return row;
    });
    if (forms.length > 12) rows.push(node('p','list-truncation',`Showing the first 12 forms. Export the report to view all ${forms.length} collected forms.`));
    $('forms-list').replaceChildren(...rows);
  }
  const resources = snapshot.resources || {};
  const groups = [['Script origins', resources.scriptOrigins], ['Frame origins', resources.frameOrigins], ['Link destinations', resources.linkOrigins]];
  $('resources-list').replaceChildren(...groups.map(([label, values]) => {
    const items = Array.isArray(values) ? values : [], group = node('div','resource-group'), heading = node('h4'); heading.append(node('span','',label),node('span','',`${items.length} listed`));
    const list = node('ul','origin-list');
    list.replaceChildren(...(items.length ? items.slice(0,8).map(value => node('li','',value)) : [node('li','empty-origin','No HTTP(S) origins listed')]));
    group.append(heading,list); if (items.length > 8) group.append(node('p','list-truncation',`${items.length-8} more origins are available in the exported report.`)); return group;
  }));
  $('local-limitations').replaceChildren(...(snapshot.limitations || []).map(value => node('li','',value)));
}
function renderNetwork(network) {
  $('network-empty').hidden = Boolean(network); $('network-content').hidden = !network;
  if (!network) return;
  $('network-time').textContent = date(network.checkedAt);
  factList($('network-facts'), [
    ['Checked origin', network.origin], ['DNS addresses', network.dns?.length ? network.dns.map(item => `${item.address} | IPv${item.family}`).join('\n') : 'Unknown - no public DNS results obtained'],
    ['HEAD status', network.http?.status ?? 'Unknown - no response received'], ['Final response origin', network.http?.finalOrigin || 'Unknown']
  ]);
  const redirects = network.http?.redirects;
  $('redirect-list').hidden = !redirects?.length;
  $('redirect-list').replaceChildren(...(redirects || []).map(item => node('p','',`${item.status} | ${item.from} -> ${item.to}`)));
  const tls = network.tls;
  $('tls-status').textContent = tls?.authorized === true ? 'Verified in this check' : tls?.authorized === false ? 'Not verified in this check' : 'Unknown / not checked';
  factList($('tls-facts'), [
    ['TLS protocol', tls?.protocol || 'Unknown'], ['Issuer',tls?.issuer || 'Unknown'], ['Certificate subject',tls?.subject || 'Unknown'], ['Valid from',tls?.validFrom ? date(tls.validFrom) : 'Unknown'], ['Valid until',tls?.validTo ? date(tls.validTo) : 'Unknown'], ['Days remaining',typeof tls?.daysRemaining === 'number' ? `${tls.daysRemaining} days` : 'Unknown'], ['Verification error',tls?.error || (tls?.authorized === true ? 'No verification error reported in this check' : 'Unknown')]
  ]);
  const headers = network.http?.headers;
  $('headers-list').replaceChildren(...headerNames.map(name => {
    const value = headers?.[name], row = node('div','header-row');
    row.append(node('span','header-name',name), node('span',`header-value${value === undefined ? ' missing' : ''}`,value === undefined ? headers ? 'Not observed in this response' : 'Unknown - response headers not obtained' : value)); return row;
  }));
  const findings = Array.isArray(network.findings) ? network.findings : [];
  if (findings.length) { const card = node('article','card'), heading = node('div','card-heading'); heading.append(node('h3','','Connection check observations'), node('span','count-tag',`${findings.length} items`)); card.append(heading,...findings.map((finding,index) => findingElement(finding,index === 0))); $('network-findings').replaceChildren(card); }
  else $('network-findings').replaceChildren();
  $('network-limitations').replaceChildren(...(network.limitations || []).map(value => node('li','',value)));
}
function renderLlm(llm) {
  $('llm-empty').hidden = Boolean(llm); $('llm-result').hidden = !llm;
  if (!llm) return;
  $('llm-provider').textContent = [llm.provider,llm.model].filter(Boolean).join(' / ');
  $('llm-summary').textContent = llm.summary || 'The model did not provide a summary.';
  $('llm-observations').replaceChildren(...(llm.observations || []).map((observation,index) => {
    const row = node('section','llm-observation'); row.append(node('h4','',`${String(index+1).padStart(2,'0')} / ${observation.title || 'Observation'}`));
    const details = node('dl'); factList(details,[['Evidence',observation.evidence,true],['Interpretation',observation.interpretation,true],['Suggestion',observation.action,true]]); row.append(details); return row;
  }));
  $('llm-unknown-block').hidden = !llm.unknowns?.length;
  $('llm-unknowns').replaceChildren(...(llm.unknowns || []).map(value => node('li','',value)));
}
function render(report) {
  state.report = report;
  $('loading-state').hidden = true;
  if (report?.error || !report?.snapshot) {
    $('report-body').hidden = true; $('unavailable-state').hidden = false;
    $('unavailable-message').textContent = report?.error || 'No page report is available. Click the extension icon on the website you want to inspect.'; controls(); return;
  }
  $('unavailable-state').hidden = true; $('report-body').hidden = false;
  renderLocal(report); renderNetwork(report.network); renderLlm(report.llm); controls();
}
function renderSettings(settings) {
  state.settings = settings; $('backend-url').value = settings.backendUrl || 'http://127.0.0.1:43187';
  $('backend-token').value = ''; $('token-state').textContent = settings.tokenSaved ? 'Saved' : 'Not saved';
  $('backend-token').placeholder = settings.tokenSaved ? 'Leave blank to keep the saved token for this address' : 'Enter the access token shown when the backend starts';
}
function closePreview() { if (state.busy) return; $('preview-dialog').close(); state.preview = null; controls(); }
$('refresh-button').addEventListener('click', () => perform('Reading the current main page again...', async () => { render(await message('REFRESH_SCAN')); success('Page refreshed. The previous LLM interpretation was cleared to avoid mixing old evidence.'); }));
$('network-button').addEventListener('click', () => perform('Checking DNS, TLS, and the root response through the local backend...', async () => { render(await message('RUN_NETWORK')); success('Network checks returned. Incomplete checks are marked unknown; review the scope notes.'); }));
$('preview-button').addEventListener('click', () => perform('Preparing the send preview; the model has not been called...', async () => {
  const preview = await message('PREPARE_LLM',{includeText:$('include-text').checked});
  render(await message('GET_REPORT')); state.preview = preview;
  $('preview-provider').textContent = preview.providerHost || 'Backend did not identify the provider'; $('preview-model').textContent = preview.model || 'Backend did not provide a model name';
  $('preview-json').textContent = JSON.stringify(preview.payload,null,2); $('preview-dialog').showModal();
}));
$('preview-confirm').addEventListener('click', () => perform('Requesting the configured model provider; please wait...', async () => {
  if (!state.preview) throw new Error('The send preview has expired. Create a new preview.');
  let report;
  try { report = await message('RUN_LLM',{previewId:state.preview.previewId}); }
  catch (error) { state.preview = null; $('preview-dialog').close(); throw error; }
  state.preview = null; $('preview-dialog').close(); render(report); success('Model interpretation is ready. Review the cited evidence and remaining unknowns.'); $('llm-result').scrollIntoView({block:'start',behavior:'smooth'});
}));
for (const id of ['dialog-close','preview-cancel']) $(id).addEventListener('click',closePreview);
$('preview-dialog').addEventListener('cancel',event => { if (state.busy) event.preventDefault(); else {state.preview = null;controls();} });
$('export-button').addEventListener('click', () => {
  if (!state.report?.snapshot || state.busy) return;
  const hostname = String(state.report.snapshot.page.hostname || 'website').replace(/[^a-zA-Z0-9.-]/g,'_').slice(0,100);
  const exportData = isDemo ? {...state.report,demo:true} : state.report;
  const url = URL.createObjectURL(new Blob([JSON.stringify(exportData,null,2)],{type:'application/json;charset=utf-8'}));
  const link = node('a'); link.href = url; link.download = `link-lens-${hostname}-${new Date().toISOString().slice(0,10)}.json`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),1000); success('Report exported. It may include page titles, origin lists, and text excerpts you chose to generate.');
});
$('settings-form').addEventListener('submit',event => {event.preventDefault();perform('Saving local backend settings...',async () => {
  const result = await message('SAVE_SETTINGS',{backendUrl:$('backend-url').value.trim(),backendToken:$('backend-token').value}); renderSettings(result); $('backend-status').textContent = 'Settings saved. Use Test connection to check the backend status.'; $('backend-status').className = 'backend-status'; success('Local backend settings saved.');
});});
$('check-backend-button').addEventListener('click', () => perform('Testing the saved local backend connection...',async () => {
  const result = await message('CHECK_BACKEND');
  const modelStatus = result.llm?.configured ? `Model configured: ${result.llm.providerHost || 'Configured provider'} / ${result.llm.model || 'Configured model'}` : 'No model configured; local and network checks are still available.';
  $('backend-status').className = 'backend-status'; $('backend-status').textContent = `Connected to the local backend.\n${modelStatus}`; success('Local backend connection succeeded. The test uses the saved address; save any changes first.');
}));
$('clear-token-button').addEventListener('click', () => perform('Clearing the access token saved in the extension...',async () => { await message('CLEAR_TOKEN'); renderSettings({...state.settings,tokenSaved:false}); $('backend-status').textContent = 'The saved extension token was cleared. Enter it again before network or model operations.';success('Saved local access token cleared.'); }));

async function initialize() {
  $('demo-badge').hidden = !isDemo; $('demo-notice').hidden = !isDemo;
  if (isDemo) {
    $('backend-status').textContent = 'Demo mode: settings are not saved and the backend is not contacted.';
    try { const response = await fetch('./demo-data.json',{cache:'no-store'}); if (!response.ok) throw new Error('Could not load demo data.'); render(await response.json()); }
    catch(error) { render({error:error.message}); showError(error); }
    controls(); return;
  }
  const tasks = [message('GET_SETTINGS').then(renderSettings)];
  if (scanId) tasks.push(message('GET_REPORT').then(render));
  else render({error:settingsOnly ? 'You are configuring the backend. To inspect a website, return to its tab and click Link Lens in the browser toolbar.' : 'No report ID was provided. Click the Link Lens extension icon on the website you want to inspect.'});
  for (const result of await Promise.allSettled(tasks)) if (result.status === 'rejected') {showError(result.reason); if (!state.report) render({error:result.reason.message});}
  if (settingsOnly) { $('settings-details').open = true; $('settings-section').scrollIntoView({block:'start'}); }
  controls();
}
initialize();
