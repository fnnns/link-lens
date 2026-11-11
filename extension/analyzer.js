/** Deterministic findings from collected facts; this is not a malware verdict. */
export function analyzeSnapshot(snapshot) {
  if (!snapshot || snapshot.version !== 1 || !snapshot.page || !snapshot.counts) throw new TypeError('The page snapshot format is invalid. Inspect the current page again.');
  const page = snapshot.page;
  let url;
  try { url = new URL(page.url); } catch { throw new TypeError('The page URL is invalid. Inspect the current page again.'); }
  if (!/^https?:$/.test(url.protocol)) throw new TypeError('Only HTTP and HTTPS pages are supported.');
  const findings = [];
  const add = (id, severity, title, evidence, recommendation) => findings.push({ id, severity, title, evidence, recommendation });
  const forms = Array.isArray(snapshot.forms) ? snapshot.forms : [];
  const counts = snapshot.counts;
  const http = url.protocol === 'http:';
  if (http) add('http-page', counts.passwordForms > 0 ? 'high' : 'medium', 'The current page uses HTTP', `The page uses HTTP${counts.passwordForms > 0 ? ` and contains ${counts.passwordForms} password forms` : ''}.`, 'For login, payment, or personal information, first verify the site through a known official HTTPS entry point.');
  if (page.hasCredentials) add('url-credentials', 'medium', 'The URL contains a user information segment', 'The original URL contained a username or password before the hostname. This part was removed from the report.', 'Check the actual hostname. Text before @ is not the website domain.');
  const insecurePassword = forms.filter(form => form.hasPassword && form.insecureAction);
  const insecureOther = forms.filter(form => !form.hasPassword && form.insecureAction);
  if (insecurePassword.length) add('password-to-http', 'high', 'Password forms declare an HTTP submission target', `${insecurePassword.length} listed password forms have an action pointing to an HTTP origin.`, 'Avoid entering passwords in these forms. Verify the correct HTTPS submission address through an official entry point.');
  if (!http && insecureOther.length) add('form-to-http', 'medium', 'Forms declare an unencrypted submission target', `${insecureOther.length} listed form actions point from this HTTPS page to an HTTP origin.`, 'Before submitting personal information, check whether the form target should use HTTPS.');
  const crossPassword = forms.filter(form => form.hasPassword && form.crossOrigin && !form.insecureAction);
  if (crossPassword.length) add('password-cross-origin', 'medium', 'Password forms submit to another origin', `${crossPassword.length} listed password forms have an action on a different origin. Cross-origin sign-in can also be part of a legitimate authentication flow.`, 'Check that the destination is the expected official identity service. This observation alone does not establish phishing.');
  if (!http && counts.httpResources > 0) add('http-resources', 'medium', 'The page declares HTTP resources', `Observed ${counts.httpResources} HTTP resource references. Actual loading is unconfirmed; the browser may upgrade or block these requests.`, 'Review the resource origins. Site maintainers should use HTTPS resources.');
  if (!http && page.secureContext === false) add('not-secure-context', 'medium', 'The browser does not treat the page as a secure context', 'The page uses HTTPS, but the browser reports isSecureContext as false. This value does not replace certificate validation.', 'Check the address bar connection state and whether the page is embedded in an insecure environment.');
  const host = url.hostname.toLowerCase();
  if (host.split('.').some(label => label.startsWith('xn--'))) add('idn-domain', 'info', 'The domain contains internationalized characters', `The browser parsed the ASCII hostname as ${host}.`, 'Verify the full domain and watch for similar-looking characters. An internationalized domain is not inherently suspicious.');
  if (/^\[.*\]$/.test(host) || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) add('ip-host', 'info', 'The current URL uses an IP address', `The actual host is ${host}, rather than a readable domain name.`, 'Confirm that this is the expected device or service. IP addresses are also common in development and internal systems.');
  if (url.port) add('custom-port', 'info', 'The page uses a custom port', `The current port is ${url.port}.`, 'Confirm that this port belongs to the expected service.');
  const externalScripts = Array.isArray(snapshot.resources?.scriptOrigins) ? snapshot.resources.scriptOrigins.filter(origin => origin !== url.origin) : [];
  if (externalScripts.length) add('third-party-scripts', 'info', 'The page references third-party script origins', `Listed ${externalScripts.length} script origins different from this page. DOM references do not prove that scripts actually ran.`, 'Review these services in the origin list. Third-party scripts may support analytics, payment, or other legitimate features.');
  if (page.canonical) {
    try { const canonicalOrigin = new URL(page.canonical).origin; if (canonicalOrigin !== url.origin) add('canonical-other-origin', 'info', 'The declared canonical URL uses another origin', `The page declares a canonical URL on ${canonicalOrigin}. This tag is supplied by the website itself.`, 'Compare it with the actual address. Cross-origin canonical URLs can also support legitimate content syndication.'); } catch { /* Ignore unparseable self-declared metadata. */ }
  }
  if (forms.some(form => !form.actionOrigin)) add('unresolved-form-action', 'info', 'Some form targets are not HTTP(S) addresses', 'Some form actions cannot be parsed as HTTP(S) URLs. Page scripts may also handle submission themselves.', 'Verify the actual request destination before submitting sensitive information.');
  const high = findings.some(finding => finding.severity === 'high');
  const medium = findings.some(finding => finding.severity === 'medium');
  return {
    findings,
    summary: {
      level: high ? 'attention' : medium ? 'review' : 'no-obvious-issues',
      headline: high ? 'Structural issues need priority review' : medium ? 'Some observations need further review' : 'No obvious structural issues were found within the checked scope',
      checkedAt: snapshot.scannedAt || new Date().toISOString()
    }
  };
}
