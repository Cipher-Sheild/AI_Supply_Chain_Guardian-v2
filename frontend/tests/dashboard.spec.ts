import {test,expect} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
test.beforeAll(async({request})=>{
 await expect.poll(async()=>{
  try{return [200,401].includes((await request.get('/api/scans')).status());}catch{return false;}
 },{timeout:60000,intervals:[500,1000,2000]}).toBe(true);
});
function clientKey(){
 const config=process.env.GUARDIAN_DEPLOYMENT_CONFIG||path.resolve('../.data/production-pass/compose.env');
 const line=fs.readFileSync(config,'utf8').split('\n').find(value=>value.startsWith('GUARDIAN_API_KEY='));
 if(!line)throw Error('Client deployment credential missing');return line.slice('GUARDIAN_API_KEY='.length).trim();
}
test.beforeEach(async({page})=>{await page.route('**/api/connection',route=>route.fulfill({json:{local_access:false}}));});
test('authenticated scan, final verdict, persisted history, PDF, and reload clears access',async({page})=>{
 await page.goto('/');await page.getByText('Deployment access',{exact:false}).click();
 await page.getByLabel('API key',{exact:true}).fill(clientKey());
 await page.getByRole('button',{name:'Use key for this session'}).click();
 await expect(page.getByLabel('API key',{exact:true})).toHaveValue('');
 await page.getByLabel('Filename',{exact:true}).fill('demo.py');
 await page.getByLabel('Artifact content').fill('import os\nos.system(input())\n');
 await page.getByRole('button',{name:'Scan artifacts',exact:true}).click();
 await expect(page.getByRole('heading',{name:'REVIEW',exact:true})).toBeVisible({timeout:90000});
 await expect(page.getByText('high · command_injection',{exact:true})).toBeVisible();
 await expect(page.getByText('Final',{exact:true})).toBeVisible();
 const downloadEvent=page.waitForEvent('download');
 await page.getByRole('button',{name:'Download audit PDF'}).click();
 const download=await downloadEvent;const pdf=await download.path();
 expect(pdf).not.toBeNull();expect(fs.readFileSync(pdf!).subarray(0,5).toString()).toBe('%PDF-');
 const storage=await page.evaluate(()=>({local:{...localStorage},session:{...sessionStorage}}));
 expect(JSON.stringify(storage).includes(clientKey())).toBe(false);
 await page.reload();await expect(page.getByText('Connection required',{exact:true})).toBeVisible();
 await expect(page.getByRole('heading',{name:'REVIEW',exact:true})).toHaveCount(0);
});
test('clearing access ignores an older history response',async({page})=>{
 let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);let started!:()=>void;
 const began=new Promise<void>(resolve=>started=resolve);
 await page.route('**/api/scans?*',async route=>{
  if(!route.request().headers()['authorization']){await route.fulfill({status:401,body:'Unauthorized'});return;}
  started();await gate;
  await route.fulfill({json:{items:[{request_id:'stale-private-id',recommendation:'reject',trust_score:0,scan_status:'final'}],has_more:false}});
 });
 await page.goto('/');await page.getByText('Deployment access',{exact:false}).click();
 await page.getByLabel('API key',{exact:true}).fill('controlled-fixture-key');
 await page.getByRole('button',{name:'Use key for this session'}).click();await began;
 await page.getByRole('button',{name:'Clear key',exact:true}).click();release();
 await page.waitForTimeout(500);await expect(page.getByText(/stale-privat/)).toHaveCount(0);
});

test('deployment import authenticates with only the client key and clears the file selection',async({page})=>{
 let authenticated=false;
 await page.route('**/api/scans?*',async route=>{
  const headers=route.request().headers();
  if(headers.authorization){expect(headers.authorization==='Bearer controlled-import-key').toBe(true);authenticated=true;}
  expect(JSON.stringify(headers).includes('provider-private-fixture')).toBe(false);
  await route.fulfill({json:{items:[],has_more:false}});
 });
 await page.goto('/');await page.getByText('Deployment access',{exact:false}).click();
 const input=page.getByLabel('Import deployment client key');
 await input.setInputFiles({name:'deployment.env',mimeType:'text/plain',buffer:Buffer.from('GUARDIAN_API_KEY=controlled-import-key\nGROQ_API_KEY=provider-private-fixture\n')});
 await expect.poll(()=>authenticated).toBe(true);
 await expect(input).toHaveValue('');
 await expect(page.getByLabel('API key',{exact:true})).toHaveValue('');
});

test('local access survives reload and exports a PDF straight from history',async({page})=>{
 await page.unroute('**/api/connection');
 await page.goto('/');
 const local=await page.getByText('Local deployment access is ready.',{exact:false}).isVisible();
 test.skip(!local,'Requires the explicitly configured local demo proxy');
 await expect(page.locator('.history-table tbody tr').first()).toBeVisible();
 const downloadEvent=page.waitForEvent('download');
 await page.getByRole('button',{name:'Download PDF ↓',exact:true}).first().click();
 const download=await downloadEvent, saved=await download.path();
 expect(fs.readFileSync(saved!).subarray(0,5).toString()).toBe('%PDF-');
 await expect(page.getByRole('status')).toContainText('Report downloaded');
 await page.reload();await expect(page.locator('.history-table tbody tr').first()).toBeVisible();
 await expect(page.getByRole('alert')).toHaveCount(0);
});

test('refresh replaces history and failed PDF exports show a useful error',async({page})=>{
 let title='first-scan';
 await page.route('**/api/scans?*',route=>route.fulfill({json:{items:[{request_id:title,recommendation:'accept',trust_score:100,scan_status:'final',detector_results:[]}],has_more:false}}));
 await page.route('**/audit.pdf',route=>route.fulfill({status:503,body:'Unavailable'}));
 await page.goto('/');await page.getByText('Deployment access',{exact:false}).first().click();
 await page.getByLabel('API key',{exact:true}).fill('fixture-key');
 await page.getByRole('button',{name:'Use key for this session'}).click();
 await expect(page.getByRole('button',{name:/first-scan/})).toBeVisible();
 title='second-scan';await page.getByRole('button',{name:'Refresh history',exact:true}).click();
 await expect(page.getByRole('button',{name:/second-scan/})).toBeVisible();
 await expect(page.getByRole('button',{name:/first-scan/})).toHaveCount(0);
 await page.getByRole('button',{name:'Download PDF ↓',exact:true}).click();
 await expect(page.getByRole('alert')).toContainText('PDF export failed (HTTP 503)');
});

test('local demo proxy rejects foreign origins and never returns a client key',async({request})=>{
 const connection=await request.get('/api/connection');const mode=await connection.json();
 test.skip(!mode.local_access,'Requires the explicitly configured local demo proxy');
 expect(JSON.stringify(mode)).not.toContain(clientKey());
 expect((await request.get('/api/scans',{headers:{Origin:'https://untrusted.example'}})).status()).toBe(403);
 expect((await request.get('/api/scans',{headers:{'Sec-Fetch-Site':'cross-site'}})).status()).toBe(403);
});

test('history layout stays inside a narrow viewport',async({page})=>{
 await page.unroute('**/api/connection');await page.setViewportSize({width:390,height:844});
 await page.goto('/');
 await expect(page.getByRole('heading',{name:'Scan history',exact:true})).toBeVisible();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
});

test('automatic refresh displays a new scan without clicking Refresh',async({page})=>{
 let next=false;
 await page.route('**/api/scans?*',route=>route.fulfill({json:{items:[{request_id:next?'automatic-new':'automatic-old',recommendation:'accept',trust_score:100,scan_status:'final',detector_results:[]}],has_more:false}}));
 await page.goto('/');await page.getByText('Deployment access',{exact:false}).click();
 await page.getByLabel('API key',{exact:true}).fill('fixture-key');await page.getByRole('button',{name:'Use key for this session'}).click();
 await expect(page.getByRole('button',{name:/automatic-ol/})).toBeVisible();next=true;
 await expect(page.getByRole('button',{name:/automatic-ne/})).toBeVisible({timeout:9000});
});

test('container report makes supplied-text scope visible outside raw JSON',async({page})=>{
 await page.route('**/api/scans?*',route=>route.fulfill({json:{items:[],has_more:false}}));
 await page.route('**/api/analyze/batch',async route=>{expect(route.request().postDataJSON().files[0].options.scan_scope).toBe('supplied_text');await route.fulfill({json:{request_id:'scope-check',trust_score:100,recommendation:'accept',scan_status:'final',explanation:'Requested configuration checked.',routing:{overall_coverage:'full'},detector_results:[{agent_name:'docker_security',status:'pass',coverage:'full',findings:[],evidence:{scan_scope:'supplied_text',scope_notice:'Image contents and CVEs were not evaluated.'}}]}});});
 await page.goto('/');await page.getByText('Deployment access',{exact:false}).click();
 await page.getByLabel('API key',{exact:true}).fill('fixture-key');await page.getByRole('button',{name:'Use key for this session'}).click();
 await expect(page.getByLabel('Container scan scope',{exact:false})).toHaveValue('resolved_images');await page.getByLabel('Container scan scope',{exact:false}).selectOption('supplied_text');await page.getByLabel('Filename',{exact:true}).fill('Dockerfile');await page.getByLabel('Artifact content').fill('FROM scratch\n');await page.getByRole('button',{name:'Scan artifacts',exact:true}).click();
 await page.locator('details.agent > summary').filter({hasText:'Docker Security'}).click();
 await expect(page.getByText('Scan scope: supplied text',{exact:true})).toBeVisible();
 await expect(page.locator('.scope-notice')).toContainText('Image contents and CVEs were not evaluated.');
});
