import { lookup as dnsLookup } from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import { isPublicAddress } from './ip.mjs';

const SELECTED_HEADERS = ['content-type','content-security-policy','content-security-policy-report-only','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-resource-policy','cross-origin-embedder-policy','server','x-powered-by'];
const REDIRECTS = new Set([301,302,303,307,308]);
const TLS_ERRORS = new Set(['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','ERR_TLS_CERT_ALTNAME_INVALID','CERT_REVOKED']);
const clean = (value, limit = 4096) => String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, limit);
const hostName = url => url.hostname.replace(/^\[|\]$/g, '');

export function normalizeOrigin(input) {
  if (typeof input !== 'string' || input.length > 2048 || /[\s\\\u0000-\u001f\u007f]/.test(input)) throw new Error('Enter a valid website origin.');
  let url;
  try { url = new URL(input); } catch { throw new Error('The website origin address format is invalid.'); }
  if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.port) throw new Error('Only HTTP/HTTPS website origins on standard ports can be inspected; credentials, paths, queries, and fragments are not accepted.');
  const host = hostName(url).toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || /\.(?:localhost|local|internal|home|test|invalid)$/i.test(host)) throw new Error('Local, internal, or reserved domains are not inspected.');
  if (isIP(host) && !isPublicAddress(host)) throw new Error('Local, internal, or reserved IP addresses are not inspected.');
  return url;
}

async function timeout(promise, ms) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('The operation timed out.'), {code:'TIMEOUT'})), ms); })]); }
  finally { clearTimeout(timer); }
}

export async function resolvePublic(url, lookup = dnsLookup, timeoutMs = 8000) {
  const host = hostName(url);
  const records = isIP(host) ? [{address:host,family:isIP(host)}] : await timeout(lookup(host,{all:true,verbatim:true}), timeoutMs);
  if (!Array.isArray(records) || !records.length || records.length > 100 || records.some(record => !isPublicAddress(record.address))) throw new Error('DNS contains non-public or invalid addresses; the connection was stopped.');
  return [...new Map(records.map(record => [record.address,{address:record.address,family:isIP(record.address)}])).values()];
}

function tlsDetails(socket) {
  if (!socket?.encrypted) return null;
  const certificate = socket.getPeerCertificate?.() || {};
  const text = object => Object.entries(object || {}).slice(0, 8).map(([key,value]) => `${key}=${clean(value,200)}`).join(', ');
  const validTo = certificate.valid_to ? new Date(certificate.valid_to) : null;
  return {
    authorized:socket.authorized === true,
    protocol:clean(socket.getProtocol?.(),60),
    issuer:text(certificate.issuer),subject:text(certificate.subject),
    validFrom:certificate.valid_from ? new Date(certificate.valid_from).toISOString() : null,
    validTo:validTo && !Number.isNaN(validTo.valueOf()) ? validTo.toISOString() : null,
    daysRemaining:validTo && !Number.isNaN(validTo.valueOf()) ? Math.floor((validTo.valueOf()-Date.now())/86400000) : null,
    fingerprint256:clean(certificate.fingerprint256,120),
  };
}

export function requestHeadPinned(url, addresses, timeoutMs = 8000) {
  return new Promise((resolve,reject) => {
    const address = addresses[0];
    if (!address || !isPublicAddress(address.address)) return reject(new Error('No public address is available.'));
    const transport = url.protocol === 'https:' ? https : http;
    let deadlineTimer;
    const clearDeadline = () => clearTimeout(deadlineTimer);
    const timeoutError = () => Object.assign(new Error('The connection timed out.'),{code:'TIMEOUT'});
    const request = transport.request({
      protocol:url.protocol,hostname:hostName(url),port:url.protocol==='https:'?443:80,path:'/',method:'HEAD',
      agent:false,rejectUnauthorized:true,maxHeaderSize:16384,autoSelectFamily:false,
      servername:isIP(hostName(url)) ? undefined : hostName(url),
      lookup(_host,options,callback) { callback(null, options?.all ? [address] : address.address, address.family); },
      headers:{'User-Agent':'LinkLensLocal/1.0 (read-only origin inspection)','Accept':'text/html, */*;q=0.1'},
    }, response => {
      try { resolve({status:response.statusCode,headers:response.headers,tls:tlsDetails(response.socket)}); }
      catch (error) { reject(error); }
      finally { clearDeadline(); response.destroy(); }
    });
    // Socket inactivity timeouts do not necessarily cover connection setup.
    // This wall-clock deadline also destroys a pre-connect stalled request.
    deadlineTimer = setTimeout(() => request.destroy(timeoutError()),timeoutMs);
    request.setTimeout(timeoutMs, () => request.destroy(timeoutError()));
    request.once('close',clearDeadline);
    request.on('error',error => { clearDeadline(); reject(error); });
    request.end();
  });
}

export async function inspectOrigin(input, dependencies = {}) {
  const initial = normalizeOrigin(input);
  const lookup = dependencies.lookup || dnsLookup;
  const requestHead = dependencies.requestHead || requestHeadPinned;
  const timeoutMs = Math.min(dependencies.timeoutMs || 12000,15000);
  const deadline = Date.now()+timeoutMs;
  const remaining = () => {
    if(Date.now()>=deadline)throw Object.assign(new Error('The operation timed out.'),{code:'TIMEOUT'});
    return Math.max(1,Math.min(8000,deadline-Date.now()));
  };
  const report = {origin:initial.origin,checkedAt:new Date().toISOString(),dns:[],http:null,tls:null,findings:[],limitations:['This root-path HEAD check sends no browser credentials; the response may differ from the current browser page.','WHOIS, domain registration dates, malicious URL databases, and the actual website owner are not checked.']};
  const add = (id,severity,title,evidence,recommendation) => report.findings.push({id,severity,title,evidence,recommendation});
  const redirects = [];
  let current = initial;
  try {
    for (let hop=0;hop<=3;hop++) {
      const addresses = await resolvePublic(current,lookup,remaining());
      if (hop===0) report.dns=addresses;
      const left=remaining();
      const response = await timeout(requestHead(current,addresses,left),left);
      const selected={};
      for (const name of SELECTED_HEADERS) if (response.headers?.[name] !== undefined) selected[name]=clean(response.headers[name]);
      report.http={status:Number(response.status),finalOrigin:current.origin,redirects,headers:selected};
      report.tls=response.tls || null;
      if (REDIRECTS.has(response.status) && response.headers?.location) {
        let destination;
        try { destination=new URL(String(response.headers.location),current); } catch { report.limitations.push('The response contains an invalid redirect address; it was not followed.');break; }
        redirects.push({from:current.origin,to:['http:','https:'].includes(destination.protocol)?destination.origin:'unsupported',status:response.status});
        if (destination.username || destination.password || destination.search || destination.hash || destination.pathname!=='/') { report.limitations.push('The root redirect includes a path, query, or credentials. Only the destination origin was recorded; it was not visited.');break; }
        if (hop===3) {report.limitations.push('The maximum of 3 redirects was reached.');break;}
        if (current.protocol==='https:' && destination.protocol==='http:') add('network-downgrade','medium','The redirect downgrades HTTPS to HTTP',`${current.origin} -> ${destination.origin}`,'Do not submit passwords or personal information through this redirect.');
        current=normalizeOrigin(destination.origin);continue;
      }
      break;
    }
  } catch (error) {
    if (TLS_ERRORS.has(error.code)) {
      report.tls={authorized:false,error:clean(error.code,80)};
      add('tls-verification-failed','high','TLS certificate verification failed',clean(error.code,80),'Stop submitting sensitive information and verify the website through an independently trusted entry point.');
    }
    report.limitations.push(error.code==='TIMEOUT'?'The network check timed out. Incomplete items remain unknown.':'Some network checks did not complete, possibly because of DNS, connection restrictions, or certificate issues.');
    if (/non-public|reserved|internal|public address/i.test(error.message)) report.limitations.push('Public-address validation rejected the target or redirect; the connection was stopped.');
  }
  if (initial.protocol==='http:') add('network-http','medium','The website origin uses HTTP',initial.origin,'Avoid entering passwords and personal information over an unencrypted connection.');
  const headers=report.http?.headers;
  const status=report.http?.status;
  if (status===405 || status===501) report.limitations.push('The website does not support HEAD. These headers may not represent the document; no GET request was made.');
  else if (headers && status>=200 && status<300) {
    if (current.protocol==='https:' && !headers['strict-transport-security']) add('header-hsts','info','HSTS was not observed in this response','The root-path HEAD response did not include Strict-Transport-Security.','This does not prove the website is dangerous. Site maintainers can inspect the actual document response received by the browser.');
    if (!headers['content-security-policy']) add('header-csp','info','CSP was not observed in this response','The root-path HEAD response did not include Content-Security-Policy.','This does not establish a vulnerability; other paths may use different policies.');
    if (!headers['x-content-type-options']) add('header-nosniff','info','A MIME sniffing restriction was not observed in this response','X-Content-Type-Options was not included.','Site maintainers can consider setting nosniff together with the correct Content-Type.');
    if (report.tls?.daysRemaining !== null && report.tls?.daysRemaining <= 14) add('tls-expiry','medium','The certificate is approaching expiration',`The certificate has approximately ${report.tls.daysRemaining} days remaining.`,'Site maintainers should check automatic renewal. This does not mean the current certificate is invalid.');
  }
  if (!report.http) report.limitations.push('No HTTP response was received. Security header checks remain unknown.');
  return report;
}
