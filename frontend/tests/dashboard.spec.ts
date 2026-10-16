import {test,expect} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
test.beforeAll(async({request})=>{
 await expect.poll(async()=>{
  try{return (await request.get('/api/scans')).status();}catch{return 0;}
 },{timeout:60000,intervals:[500,1000,2000]}).toBe(401);
});
function clientKey(){
 const config=process.env.GUARDIAN_DEPLOYMENT_CONFIG||path.resolve('../.data/production-pass/compose.env');
 const line=fs.readFileSync(config,'utf8').split('\n').find(value=>value.startsWith('GUARDIAN_API_KEY='));
 if(!line)throw Error('Client deployment credential missing');return line.slice('GUARDIAN_API_KEY='.length).trim();
}
test('authenticated scan, final verdict, persisted history, PDF, and reload clears access',async({page})=>{
 await page.goto('/');await page.getByText('Deployment access',{exact:true}).click();
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
 await page.reload();await expect(page.getByRole('alert')).toContainText('401');
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
 await page.goto('/');await page.getByText('Deployment access',{exact:true}).click();
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
 await page.goto('/');await page.getByText('Deployment access',{exact:true}).click();
 const input=page.getByLabel('Import deployment client key');
 await input.setInputFiles({name:'deployment.env',mimeType:'text/plain',buffer:Buffer.from('GUARDIAN_API_KEY=controlled-import-key\nGROQ_API_KEY=provider-private-fixture\n')});
 await expect.poll(()=>authenticated).toBe(true);
 await expect(input).toHaveValue('');
 await expect(page.getByLabel('API key',{exact:true})).toHaveValue('');
});
