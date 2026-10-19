import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import {readFileSync,lstatSync} from 'node:fs';
// Explicitly opt-in, loopback-only demo access. The client credential never reaches the browser.
const configPath=process.env.GUARDIAN_DASHBOARD_CLIENT_CONFIG;
const comparisonPath=process.env.GUARDIAN_COMPARISON_LOG;
let clientKey='';
if(configPath){
 const stat=lstatSync(configPath);
 if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||stat.size>65536)throw Error('Dashboard client configuration must be a private regular file');
 const keys=readFileSync(configPath,'utf8').split(/\r?\n/).filter(l=>l.startsWith('GUARDIAN_API_KEY=')).map(l=>l.slice(17).trim());
 if(keys.length!==1||!keys[0]||/[\s"']/.test(keys[0]))throw Error('Invalid dashboard client configuration');
 clientKey=keys[0];
}
const target=process.env.TRUST_ENGINE_URL||'http://127.0.0.1:8000';
if(clientKey&&!['127.0.0.1','localhost','[::1]'].includes(new URL(target).hostname))throw Error('Local demo proxy requires a loopback backend');
export default defineConfig({plugins:[react(),{name:'guardian-local-access',configureServer(server){
 if(clientKey&&server.config.server.host!=='127.0.0.1')throw Error('Authenticated demo dashboard must bind to 127.0.0.1');
 server.middlewares.use(async (req,res,next)=>{
  // Canonicalize browser navigation before the authenticated proxy's Host checks.
  // Keep API requests subject to the existing same-origin restrictions.
  const localAlias=req.headers.host?.match(/^localhost:(\d+)$/);
  if(clientKey&&localAlias&&(req.method==='GET'||req.method==='HEAD')&&!req.url?.startsWith('/api/')){
   res.statusCode=307;
   res.setHeader('Location',`http://127.0.0.1:${localAlias[1]}${req.url||'/'}`);
   res.end();return;
  }
  if(!req.url?.startsWith('/api/'))return next();
  const host=req.headers.host;
  if(clientKey&&(!host||!/^127\.0\.0\.1:\d+$/.test(host)||req.headers['sec-fetch-site']==='cross-site'||(req.headers.origin&&req.headers.origin!==`http://${host}`))){res.statusCode=403;res.end('Same-origin local access required');return;}
  if(req.url==='/api/connection'){res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify({local_access:!!clientKey}));return;}
  if(req.url==='/api/history-summary'){
   res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
   if(!clientKey){res.statusCode=401;res.end(JSON.stringify({error:'Local deployment access required'}));return;}
   try{
    const ids=new Set<string>();let attention=0,offset=0;
    while(true){
     const response=await fetch(`${target}/scans?limit=100&offset=${offset}`,{headers:{Authorization:`Bearer ${clientKey}`},signal:AbortSignal.timeout(10000)});
     if(!response.ok)throw Error('History unavailable');
     const data=await response.json();
     if(!Array.isArray(data.items))throw Error('Invalid history');
     for(const item of data.items){if(!ids.has(item.request_id)){ids.add(item.request_id);if(item.recommendation!=='accept')attention++;}}
     if(!data.has_more)break;
     if(!data.items.length||offset>=100000)throw Error('History summary incomplete');
     offset+=100;
    }
    res.end(JSON.stringify({total:ids.size,attention}));
   }catch{res.statusCode=503;res.end(JSON.stringify({error:'Full history count unavailable'}));}
   return;
  }
  if(req.url==='/api/comparison-runs'){
   res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
   if(!clientKey||!comparisonPath){res.end(JSON.stringify({enabled:false,items:[]}));return;}
   try{
    const stat=lstatSync(comparisonPath);
    if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077)||stat.size>8*1048576)throw Error('Invalid comparison log');
    const items=readFileSync(comparisonPath,'utf8').trim().split('\n').filter(Boolean).slice(-1000).flatMap(line=>{
     try{
      const row=JSON.parse(line);
      const summary=(value:any)=>value&&({scan_id:value.scan_id,score:value.score,recommendation:value.recommendation,method:value.method,decision:value.decision,reason:value.reason});
      return [{timestamp:row.timestamp,run:row.run,filenames:row.filenames,relative_filenames:row.relative_filenames,weighted:summary(row.weighted),ml:summary(row.ml)}];
     }catch{return [];}
    });
    res.end(JSON.stringify({enabled:true,items}));
   }catch{res.statusCode=503;res.end(JSON.stringify({error:'Comparison history unavailable'}));}
   return;
  }
  next();
 });
}}],server:{host:'127.0.0.1',port:3000,proxy:{'/api':{target,changeOrigin:true,rewrite:path=>path.replace(/^\/api/,''),configure(proxy){proxy.on('proxyReq',(outgoing)=>{if(clientKey)outgoing.setHeader('Authorization','Bearer '+clientKey);});}}}}});
