import http from 'node:http';
import { timingSafeEqual, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { makeConfig } from './config.mjs';
import { inspectOrigin } from './network.mjs';
import { analyzeWithLlm } from './llm.mjs';

const EXTENSION_ORIGIN=/^chrome-extension:\/\/[a-p]{32}$/;
const failure=(status,message)=>Object.assign(new Error(message),{status});
function tokenMatches(received,expected) {
  if(typeof received!=='string'||!received.startsWith('Bearer '))return false;
  const a=Buffer.from(received.slice(7)),b=Buffer.from(expected);
  return a.length===b.length&&timingSafeEqual(a,b);
}
function readJson(request,limit) {
  return new Promise((resolve,reject)=>{
    const chunks=[];let length=0,failed=false;
    if(!/^application\/json(?:\s*;|$)/i.test(request.headers['content-type']||''))return reject(failure(415,'Requests must use application/json.'));
    request.on('data',chunk=>{
      length+=chunk.length;
      if(length>limit){if(!failed){failed=true;reject(failure(413,'The request body is too large.'));}return;}
      if(!failed)chunks.push(chunk);
    });
    request.on('end',()=>{
      if(failed)return;
      try {const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!body||typeof body!=='object'||Array.isArray(body))throw new Error();resolve(body);}
      catch{reject(failure(400,'The request JSON is invalid.'));}
    });
    request.on('error',()=>reject(failure(400,'The request could not be read.')));
    request.on('aborted',()=>reject(failure(400,'The request was cancelled.')));
  });
}

export function createApp(overrides={},dependencies={}) {
  const config=makeConfig(overrides);
  const configurationId=randomBytes(18).toString('base64url');
  const inspect=dependencies.inspect || ((origin)=>inspectOrigin(origin,{timeoutMs:config.networkTimeoutMs,...dependencies.network}));
  const analyze=dependencies.analyze || ((report)=>analyzeWithLlm(report,config,dependencies.llm));
  let active=0;const starts=[];
  const app=http.createServer(async(request,response)=>{
    const send=(status,payload)=>{if(response.writableEnded)return;response.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});response.end(JSON.stringify(payload));};
    try {
      const port=app.address()?.port || config.port;
      if(![`127.0.0.1:${port}`,`localhost:${port}`].includes(String(request.headers.host||'').toLowerCase()))throw failure(403,'Only requests addressed to the local backend are accepted.');
      const origin=request.headers.origin;
      if(origin!==undefined&&!EXTENSION_ORIGIN.test(origin))throw failure(403,'Only browser extension origins are accepted.');
      if(origin){response.setHeader('Access-Control-Allow-Origin',origin);response.setHeader('Vary','Origin');}
      if(request.method==='OPTIONS'){
        if(!origin || !['/inspect','/analyze','/health'].includes(request.url))throw failure(403,'The preflight origin or path is invalid.');
        response.writeHead(204,{'Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Max-Age':'600','Access-Control-Allow-Private-Network':'true'});response.end();return;
      }
      if(request.method==='GET'&&request.url==='/health'){
        send(200,{ok:true,version:'1.0.0',networkAvailable:true,llm:{configured:config.llmConfigured,providerHost:config.providerHost,model:config.llmModel,configurationId},tokenRequired:true});return;
      }
      if(request.method!=='POST'||!['/inspect','/analyze'].includes(request.url))throw failure(404,'The endpoint was not found.');
      if(!tokenMatches(request.headers.authorization,config.token))throw failure(401,'The local connection token is incorrect. Enter the token shown in the backend window in the extension settings.');
      const now=Date.now();while(starts.length&&starts[0]<now-60000)starts.shift();
      if(starts.length>=config.rateLimit)throw failure(429,'Too many requests. Try again later.');
      if(active>=config.maxConcurrent)throw failure(429,'The backend is processing other checks. Try again shortly.');
      starts.push(now);active++;
      try {
        const body=await readJson(request,config.maxBodyBytes);
        const result=request.url==='/inspect'?await inspect(body.origin):await analyze(body.report);
        send(200,result);
      } finally {active--;}
    } catch(error) {
      const known=Number.isInteger(error.status)&&error.status>=400&&error.status<600;
      const status=known?error.status:400;
      const message=known?error.message:/website origin|not inspect|standard ports|address format|missing.*report|missing.*valid|report is required/i.test(error.message)?error.message:'The check could not be completed. Verify the input and local configuration.';
      send(status,{ok:false,error:message});
    }
  });
  app.headersTimeout=10000;app.requestTimeout=15000;app.keepAliveTimeout=5000;
  Object.defineProperty(app,'backendConfig',{value:config,enumerable:false});
  return app;
}

export async function startBackend(overrides={}) {
  const app=createApp(overrides);const config=app.backendConfig;
  await new Promise((resolve,reject)=>{app.once('error',reject);app.listen(config.port,config.host,resolve);});
  console.log(`Link Lens local backend: http://127.0.0.1:${app.address().port}`);
  console.log(`Local connection token (copy to extension settings): ${config.token}`);
  console.log(config.llmConfigured?`LLM configured: ${config.providerHost} / ${config.llmModel}`:'LLM is not configured. Local page checks and public network checks are still available.');
  return app;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  startBackend().catch(error=>{console.error(error.code==='EADDRINUSE'?'The port is already in use. Stop the existing backend or change LINK_LENS_PORT.':'The backend could not start. Check the configuration.');process.exitCode=1;});
}
