/** Runs in the active page's isolated world. Keep every dependency inside this function. */
export function collectPage(includeText = false) {
  const LIMITS = { forms: 100, origins: 64, excerpt: 6000 };
  const cleanText = (value, length) => String(value || '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, length);
  const current = new URL(location.href);
  const webUrl = (value) => {
    try {
      const url = new URL(value, current.href);
      return /^https?:$/.test(url.protocol) ? url : null;
    } catch { return null; }
  };
  const cleanUrl = (value) => {
    const url = webUrl(value);
    if (!url) return '';
    url.username = ''; url.password = ''; url.search = ''; url.hash = '';
    return url.href;
  };
  const list = selector => Array.from(document.querySelectorAll(selector));
  const attribute = (node, name) => node.getAttribute(name) || '';
  const origins = values => Array.from(new Set(values.map(value => webUrl(value)?.origin).filter(Boolean)));
  const allLinks = list('a[href]');
  const allForms = list('form');
  const allScripts = list('script');
  const externalScripts = list('script[src]');
  const allFrames = list('iframe');
  const scriptOrigins = origins(externalScripts.map(node => attribute(node, 'src')));
  const frameOrigins = origins(allFrames.map(node => attribute(node, 'src')).filter(Boolean));
  const linkOrigins = origins(allLinks.map(node => attribute(node, 'href')));
  const limitations = [
    'Only the current top-level DOM snapshot is inspected; cross-origin frame contents, closed shadow roots, and later dynamic changes are not inspected.',
    'Input values, cookies, and website storage were not read; no off-page network requests were made.',
    'Declared resources do not prove successful loading; the browser may upgrade or block HTTP resources.',
    'Local checks do not inspect certificates, response headers, domain registration dates, or threat lists; scripts or submit buttons can override form targets.'
  ];
  let passwordForms = 0;
  const forms = [];
  for (let index = 0; index < allForms.length; index++) {
    const form = allForms[index];
    const fields = Array.from(form.elements || form.querySelectorAll('input, select, textarea, button'));
    const fieldTypes = Array.from(new Set(fields.map(field => {
      const tag = String(field.tagName || '').toLowerCase();
      return tag === 'input' ? (attribute(field, 'type').toLowerCase() || 'text') : tag;
    }).filter(Boolean))).slice(0, 20);
    const hasPassword = fields.some(field => String(field.tagName || '').toLowerCase() === 'input' && attribute(field, 'type').toLowerCase() === 'password');
    if (hasPassword) passwordForms++;
    if (index >= LIMITS.forms) continue;
    const action = webUrl(attribute(form, 'action') || current.href);
    forms.push({
      actionOrigin: action?.origin || null,
      method: (attribute(form, 'method') || 'get').toUpperCase().slice(0, 20),
      hasPassword,
      fieldTypes,
      fieldCount: fields.length,
      crossOrigin: Boolean(action && action.origin !== current.origin),
      insecureAction: action?.protocol === 'http:'
    });
  }
  if (allForms.length > LIMITS.forms) limitations.push(`${allForms.length} forms were observed; detailed targets are listed for the first ${LIMITS.forms}.`);
  if ([scriptOrigins, frameOrigins, linkOrigins].some(values => values.length > LIMITS.origins)) limitations.push(`Each resource category lists at most ${LIMITS.origins} distinct origins; list truncation does not affect counts.`);
  const resourceNodes = list('script[src], link[rel="stylesheet"][href], link[rel="preload"][href], img[src], iframe[src], video[src], audio[src], source[src], object[data], embed[src]');
  const canonical = document.querySelector('link[rel~="canonical"]');
  const description = document.querySelector('meta[name="description"]');
  const generator = document.querySelector('meta[name="generator"]');
  const snapshot = {
    version: 1,
    scannedAt: new Date().toISOString(),
    page: {
      url: cleanUrl(current.href),
      origin: current.origin,
      hostname: current.hostname,
      title: cleanText(document.title, 300),
      protocol: current.protocol,
      lang: cleanText(document.documentElement?.lang, 64),
      description: cleanText(description && attribute(description, 'content'), 500),
      secureContext: Boolean(window.isSecureContext),
      canonical: canonical ? cleanUrl(attribute(canonical, 'href')) : '',
      generator: cleanText(generator && attribute(generator, 'content'), 200),
      hasCredentials: Boolean(current.username || current.password),
      queryParameterCount: Array.from(current.searchParams.keys()).length
    },
    counts: {
      links: allLinks.length,
      externalLinks: allLinks.filter(node => { const url = webUrl(attribute(node, 'href')); return url && url.origin !== current.origin; }).length,
      forms: allForms.length,
      passwordForms,
      scripts: allScripts.length,
      externalScripts: externalScripts.length,
      inlineScripts: allScripts.length - externalScripts.length,
      externalScriptsWithoutIntegrity: externalScripts.filter(node => !attribute(node, 'integrity')).length,
      iframes: allFrames.length,
      httpResources: resourceNodes.filter(node => webUrl(attribute(node, String(node.tagName || '').toLowerCase() === 'object' ? 'data' : String(node.tagName || '').toLowerCase() === 'link' ? 'href' : 'src'))?.protocol === 'http:').length,
      downloads: allLinks.filter(node => node.hasAttribute('download')).length
    },
    forms,
    resources: {
      scriptOrigins: scriptOrigins.slice(0, LIMITS.origins),
      frameOrigins: frameOrigins.slice(0, LIMITS.origins),
      linkOrigins: linkOrigins.slice(0, LIMITS.origins)
    },
    limitations
  };
  if (includeText) {
    const clone = document.body?.cloneNode(true);
    if (clone) {
      clone.querySelectorAll('input, textarea, select, button, option, script, style, noscript, template, iframe, [contenteditable], [hidden], [aria-hidden="true"], [data-private]').forEach(node => node.remove());
      snapshot.excerpt = cleanText(clone.textContent, 24000)
        .replace(/[A-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,}/gi, '[email redacted]')
        .replace(/(?:\+?\d[\d ()-]{6,}\d)/g, '[number redacted]')
        .replace(/\b(?:sk-[A-Za-z0-9_-]{12,}|(?:Bearer|token|api[_ -]?key|password|secret)\s*[:=]\s*["']?[^\s"'<>]{6,})/gi, '[possible key redacted]')
        .replace(/\b[A-Za-z0-9_-]{40,}\b/g, '[long identifier redacted]')
        .replace(/\s+/g, ' ').slice(0, LIMITS.excerpt);
    } else snapshot.excerpt = '';
    limitations.push('The text excerpt was generated only after opt-in. Form fields were removed and emails, numbers, and keys were redacted where recognized, but it may still contain personal or confidential content. Review the preview before sending.');
  }
  return snapshot;
}
