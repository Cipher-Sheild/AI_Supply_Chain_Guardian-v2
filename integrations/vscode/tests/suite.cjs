const vscode=require('vscode');
const assert=require('node:assert/strict');
const http=require('node:http');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check){for(let i=0;i<100;i++){if(check())return;await delay(100);}throw Error('Editor diagnostics timed out');}
exports.run=async()=>{
 let calls=0,mode='reject';
 const server=http.createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  if(req.url!=='/analyze'){res.writeHead(404).end();return;}
  assert.equal(req.headers.authorization,'Bearer controlled-editor-key');
  calls++;const artifact=JSON.parse(body);assert.match(artifact.filename,/fixture.py$/);
  if(mode==='unavailable'){res.writeHead(503).end();return;}
  if(mode==='delayed')await delay(500);
  res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify({request_id:'editor-test',scan_status:'final',recommendation:'reject',trust_score:0,
   explanation:'Dangerous shell execution',detector_results:[{agent_name:'code_security',status:'ok',findings:[{severity:'high',location:'fixture.py:2',category:'command_injection',reason:'Untrusted command'}]}]}));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const temporary=await fs.mkdtemp(path.join(os.tmpdir(),'guardian-editor-'));
 const uri=vscode.Uri.file(path.join(temporary,'fixture.py'));
 const config=vscode.workspace.getConfiguration('guardian');
 const prior={serverUrl:config.get('serverUrl'),scanOnSave:config.get('scanOnSave')};
 try{
  await config.update('serverUrl',`http://127.0.0.1:${server.address().port}`,vscode.ConfigurationTarget.Global);
  await config.update('scanOnSave',true,vscode.ConfigurationTarget.Global);
  const extension=vscode.extensions.getExtension('guardian-local.ai-supply-chain-guardian');
  assert.ok(extension);await extension.activate();
 const commands=await vscode.commands.getCommands(true);
 assert.ok(commands.includes('guardian.showComparison'),'Live comparison command must be registered');
 await vscode.commands.executeCommand('guardian.showComparison');
 console.log('Guardian extension host: live comparison Output command available.');
  const clientConfig=path.join(temporary,'client.env');
  await fs.writeFile(clientConfig,'GUARDIAN_API_KEY=controlled-editor-key\nGROQ_API_KEY=must-never-be-imported\n',{mode:0o600});
  await vscode.commands.executeCommand('guardian.importDeploymentKey',clientConfig);
  await fs.writeFile(uri.fsPath,'import os\nos.system(input())\n');
  const document=await vscode.workspace.openTextDocument(uri);await vscode.window.showTextDocument(document);
  await vscode.commands.executeCommand('guardian.scanActive');
  let issues=vscode.languages.getDiagnostics(uri).filter(d=>d.source==='Guardian');
  assert.equal(issues.length,1);assert.equal(issues[0].range.start.line,1);
  assert.equal(issues[0].severity,vscode.DiagnosticSeverity.Error);
  const before=calls;
  const edit=new vscode.WorkspaceEdit();edit.insert(uri,new vscode.Position(2,0),'# saved\n');
  await vscode.workspace.applyEdit(edit);await document.save();
  await until(()=>calls>before);
  mode='unavailable';await vscode.commands.executeCommand('guardian.scanActive');
  await until(()=>vscode.languages.getDiagnostics(uri).some(d=>d.message.includes('review required')));
  if(process.env.GUARDIAN_EDITOR_CONFIG){
   await config.update('serverUrl','http://127.0.0.1:18808',vscode.ConfigurationTarget.Global);
   await vscode.commands.executeCommand('guardian.importDeploymentKey',process.env.GUARDIAN_EDITOR_CONFIG);
   await vscode.commands.executeCommand('guardian.scanActive');
   assert.ok(vscode.languages.getDiagnostics(uri).some(d=>d.source==='Guardian'&&d.message.includes('code_security')));
   console.log('Guardian extension host: authenticated deployed API scan passed.');
  }
  await config.update('serverUrl',`http://127.0.0.1:${server.address().port}`,vscode.ConfigurationTarget.Global);
  await vscode.commands.executeCommand('guardian.importDeploymentKey',clientConfig);
  mode='delayed';const initialCalls=calls;
  const pending=vscode.commands.executeCommand('guardian.scanActive');await until(()=>calls>initialCalls);
  await vscode.commands.executeCommand('guardian.clearApiKey');await pending;await delay(600);
  assert.equal(vscode.languages.getDiagnostics(uri).length,0);
  console.log('Guardian extension host: clearing credentials cancels stale scans and diagnostics.');
  console.log('Guardian extension host: active command, diagnostic location, scan-on-save, and unavailable-service review passed.');
 }finally{
  await vscode.commands.executeCommand('guardian.clearApiKey');
  await vscode.commands.executeCommand('workbench.action.closeAllEditors');
  for(const [name,value] of Object.entries(prior))await config.update(name,value,vscode.ConfigurationTarget.Global);
  await new Promise(resolve=>server.close(resolve));await fs.rm(temporary,{recursive:true,force:true});
 }
};
