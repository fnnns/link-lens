const scalar = (value,limit=600) => typeof value==='string' ? value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,' ').slice(0,limit) : '';
const redact = value => scalar(value,6000)
  .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,'[email redacted]')
  .replace(/\b(?:sk|ghp|github_pat)[-_][A-Za-z0-9_-]{16,}\b/g,'[key redacted]')
  .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]{12,}/gi,'Bearer [redacted]')
  .replace(/([?&](?:token|key|api_key|access_token|session|auth|secret|code)=)[^&\s;"']+/gi,'$1[redacted]')
  .replace(/\b(?:\+?\d[\d ()-]{8,}\d)\b/g,'[long number redacted]');

function originOnly(value) {
  if (typeof value!=='string' || value.length>2048) return '';
  try {const url=new URL(value);return ['http:','https:'].includes(url.protocol) ? url.origin : '';} catch{return '';}
}

export function sanitizeReport(raw) {
  if (!raw || typeof raw!=='object' || Array.isArray(raw)) throw new Error('A report is required for analysis.');
  const origin=originOnly(raw.origin);
  if (!origin) throw new Error('The report is missing a valid website origin.');
  const report={origin};
  if (raw.page && typeof raw.page==='object') {
    const page={};
    if (typeof raw.page.title==='string') page.title=redact(raw.page.title).slice(0,200);
    if (typeof raw.page.description==='string') page.description=redact(raw.page.description).slice(0,600);
    if (typeof raw.page.excerpt==='string') page.excerpt=redact(raw.page.excerpt);
    if(Object.keys(page).length)report.page=page;
  }
  if(raw.counts && typeof raw.counts==='object') {
    report.counts={};
    for(const name of ['links','externalLinks','forms','passwordForms','scripts','externalScripts','inlineScripts','iframes','httpResources','downloads']) {
      if(Number.isSafeInteger(raw.counts[name])&&raw.counts[name]>=0)report.counts[name]=Math.min(raw.counts[name],1000000);
    }
  }
  if(Array.isArray(raw.forms)) report.forms=raw.forms.slice(0,30).filter(item=>item&&typeof item==='object').map(item=>({actionOrigin:originOnly(item.actionOrigin),method:scalar(item.method,10),hasPassword:item.hasPassword===true,fieldTypes:Array.isArray(item.fieldTypes)?item.fieldTypes.slice(0,20).map(value=>scalar(value,40)):[],fieldCount:Number.isSafeInteger(item.fieldCount)?Math.max(0,Math.min(item.fieldCount,10000)):0,crossOrigin:item.crossOrigin===true,insecureAction:item.insecureAction===true}));
  if(raw.resources && typeof raw.resources==='object') {
    report.resources={};
    for(const name of ['scriptOrigins','frameOrigins','linkOrigins'])if(Array.isArray(raw.resources[name]))report.resources[name]=[...new Set(raw.resources[name].slice(0,30).map(originOnly).filter(Boolean))];
  }
  if(Array.isArray(raw.localFindings))report.localFindings=raw.localFindings.slice(0,40).filter(item=>item&&typeof item==='object').map(item=>({id:scalar(item.id,80),severity:['high','medium','info'].includes(item.severity)?item.severity:'info',title:scalar(item.title,200),evidence:redact(item.evidence).slice(0,1000),recommendation:scalar(item.recommendation,800)}));
  if(raw.network && typeof raw.network==='object') {
    const source=raw.network;const network={origin:originOnly(source.origin)};
    if(Array.isArray(source.dns))network.dns=source.dns.slice(0,16).filter(item=>item&&typeof item.address==='string').map(item=>({address:scalar(item.address,64),family:item.family===6?6:4}));
    if(source.http&&typeof source.http==='object') {
      network.http={status:Number.isInteger(source.http.status)?source.http.status:null,finalOrigin:originOnly(source.http.finalOrigin),headers:{}};
      for(const name of ['content-type','content-security-policy','content-security-policy-report-only','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-resource-policy','cross-origin-embedder-policy','server','x-powered-by']) {
        if(typeof source.http.headers?.[name]==='string')network.http.headers[name]=redact(source.http.headers[name]).slice(0,1200);
      }
      if(Array.isArray(source.http.redirects))network.http.redirects=source.http.redirects.slice(0,4).filter(item=>item&&typeof item==='object').map(item=>({from:originOnly(item.from),to:originOnly(item.to),status:Number.isInteger(item.status)?item.status:null}));
    }
    if(source.tls&&typeof source.tls==='object')network.tls={authorized:source.tls.authorized===true,protocol:scalar(source.tls.protocol,40),issuer:scalar(source.tls.issuer,400),subject:scalar(source.tls.subject,400),validFrom:scalar(source.tls.validFrom,60),validTo:scalar(source.tls.validTo,60),daysRemaining:Number.isFinite(source.tls.daysRemaining)?source.tls.daysRemaining:null};
    if(Array.isArray(source.limitations))network.limitations=source.limitations.slice(0,12).map(value=>scalar(value,400));
    if(Array.isArray(source.findings))network.findings=source.findings.slice(0,20).filter(item=>item&&typeof item==='object').map(item=>({id:scalar(item.id,80),severity:['high','medium','info'].includes(item.severity)?item.severity:'info',title:scalar(item.title,200),evidence:redact(item.evidence).slice(0,1000),recommendation:scalar(item.recommendation,800)}));
    report.network=network;
  }
  return report;
}
