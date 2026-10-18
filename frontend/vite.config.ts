import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import {readFileSync,lstatSync} from 'node:fs';
// Explicitly opt-in, loopback-only demo access. The client credential never reaches the browser.
const configPath=process.env.GUARDIAN_DASHBOARD_CLIENT_CONFIG;
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
 server.middlewares.use((req,res,next)=>{
  if(!req.url?.startsWith('/api/'))return next();
  const host=req.headers.host;
  if(clientKey&&(!host||!/^127\.0\.0\.1:\d+$/.test(host)||req.headers['sec-fetch-site']==='cross-site'||(req.headers.origin&&req.headers.origin!==`http://${host}`))){res.statusCode=403;res.end('Same-origin local access required');return;}
  if(req.url==='/api/connection'){res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');res.end(JSON.stringify({local_access:!!clientKey}));return;}
  next();
 });
}}],server:{host:'127.0.0.1',port:3000,proxy:{'/api':{target,changeOrigin:true,rewrite:path=>path.replace(/^\/api/,''),configure(proxy){proxy.on('proxyReq',(outgoing)=>{if(clientKey)outgoing.setHeader('Authorization','Bearer '+clientKey);});}}}}});
