import * as vscode from 'vscode';
import * as fs from 'node:fs/promises';
type Scan = { request_id: string; scan_status: string; recommendation: string; trust_score: number; explanation: string; detector_results: { agent_name: string; status: string; findings: {severity: string; location?: string; reason?: string; category: string}[] }[] };
export function activate(context: vscode.ExtensionContext) {
  const diagnostics=vscode.languages.createDiagnosticCollection('guardian');
  const output=vscode.window.createOutputChannel('Guardian');
  const generations=new Map<string,number>();
  const saveTimers=new Map<string,ReturnType<typeof setTimeout>>();
  const activeControllers=new Map<string,AbortController>();
  function cancelScans(){
    for(const [id,generation] of generations)generations.set(id,generation+1);
    for(const controller of activeControllers.values())controller.abort();activeControllers.clear();
    for(const timer of saveTimers.values())clearTimeout(timer);saveTimers.clear();
  }
  function invalidateScans(){cancelScans();diagnostics.clear();output.clear();}
  context.subscriptions.push(vscode.commands.registerCommand('guardian.setApiKey',async()=>{
    const key=await vscode.window.showInputBox({prompt:'Guardian API key (stored in editor secret storage; empty clears it)',password:true,ignoreFocusOut:true});
    if(key===undefined)return;
    if(key)await context.secrets.store('guardian.apiKey',key);else await context.secrets.delete('guardian.apiKey');
    invalidateScans();
  }));
  context.subscriptions.push(vscode.commands.registerCommand('guardian.importDeploymentKey',async(path?:string)=>{
    const selected=path ? vscode.Uri.file(path) : (await vscode.window.showOpenDialog({canSelectMany:false,title:'Select private Guardian deployment configuration'}))?.[0];
    if(!selected)return;
    try{
      const stat=await fs.lstat(selected.fsPath);
      if(!stat.isFile()||stat.isSymbolicLink()||stat.size>65536)throw new Error('Select a regular configuration file under 64 KiB.');
      if(process.platform!=='win32'&&(stat.mode&0o077)!==0)throw new Error('Configuration must be private: chmod 600.');
      const text=await fs.readFile(selected.fsPath,'utf8');
      const keys=text.split(/\r?\n/).filter(line=>/^GUARDIAN_API_KEY=/.test(line)).map(line=>line.slice('GUARDIAN_API_KEY='.length).trim());
      if(keys.length!==1||!keys[0]||/[\s"']/.test(keys[0]))throw new Error('A single unquoted GUARDIAN_API_KEY is required.');
      await context.secrets.store('guardian.apiKey',keys[0]);
      invalidateScans();
      vscode.window.showInformationMessage('Guardian client key imported into editor secret storage.');
    }catch(error){vscode.window.showErrorMessage('Guardian: deployment key import failed. '+String(error));}
  }));
  context.subscriptions.push(vscode.commands.registerCommand('guardian.clearApiKey',async()=>{
    await context.secrets.delete('guardian.apiKey');
    invalidateScans();
    vscode.window.showInformationMessage('Guardian client key cleared.');
  }));
  async function scanDocument(document:vscode.TextDocument){
    const id=document.uri.toString(),generation=(generations.get(id)||0)+1;generations.set(id,generation);
    const version=document.version, content=document.getText();
    if(Buffer.byteLength(content,'utf8')>262144){vscode.window.showErrorMessage('Guardian: artifact exceeds 256 KiB.');return;}
    const config=vscode.workspace.getConfiguration('guardian',document.uri),base=String(config.get('serverUrl')).replace(/\/$/,'');
    let endpoint:URL;
    try{endpoint=new URL(base);}catch{vscode.window.showErrorMessage("Guardian: invalid server URL.");return;}
    if(!['http:','https:'].includes(endpoint.protocol)){vscode.window.showErrorMessage('Guardian: HTTP(S) server URL required.');return;}
    if(endpoint.username||endpoint.password){vscode.window.showErrorMessage('Guardian: credentials in URLs are refused.');return;}
    const apiKey=await context.secrets.get('guardian.apiKey');
    if(apiKey&&endpoint.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(endpoint.hostname)){vscode.window.showErrorMessage('Guardian: authenticated remote connections require HTTPS.');return;}
    await vscode.window.withProgress({location:vscode.ProgressLocation.Notification,title:'Guardian scanning artifact',cancellable:true},async(progress,token)=>{
      activeControllers.get(id)?.abort();
      const controller=new AbortController();activeControllers.set(id,controller);const subscription=token.onCancellationRequested(()=>controller.abort());
      async function request(path:string,payload?:unknown):Promise<Scan>{
        const timer=setTimeout(()=>controller.abort(),12000);
        try{const headers:Record<string,string>={};if(payload)headers['Content-Type']='application/json';if(apiKey)headers['Authorization']='Bearer '+apiKey;
          const response=await fetch(base+path,{redirect:'error',signal:controller.signal,method:payload?'POST':'GET',headers,body:payload?JSON.stringify(payload):undefined});if(!response.ok)throw new Error('HTTP '+response.status);return await response.json() as Scan;}finally{clearTimeout(timer);}
      }
      try{
        let scan=await request('/analyze',{filename:document.fileName,content});
        const deadline=Date.now()+Number(config.get('finalTimeoutSeconds'))*1000;
        while(scan.scan_status==='provisional' && Date.now()<deadline){
          progress.report({message:'Provisional '+scan.recommendation+'; waiting for judge'});
          await new Promise(resolve=>setTimeout(resolve,1000));if(token.isCancellationRequested)throw new Error('Cancelled');
          scan=await request('/scans/'+encodeURIComponent(scan.request_id));
        }
        if(scan.scan_status!=='final')throw new Error('Still provisional; review required');
        if(document.isClosed||generations.get(id)!==generation)return;
        if(document.version!==version){vscode.window.showWarningMessage('Guardian: document changed during scan; scan again.');return;}
        const issues:vscode.Diagnostic[]=[];
        for(const agent of scan.detector_results)for(const finding of agent.findings){
          const match=finding.location?.match(/:(\d+)$/),line=Math.max(0,Math.min(document.lineCount-1,Number(match?.[1]||1)-1));
          const severity=['critical','high'].includes(finding.severity)?vscode.DiagnosticSeverity.Error:vscode.DiagnosticSeverity.Warning;
          const diagnostic=new vscode.Diagnostic(document.lineAt(line).range,`${agent.agent_name}: ${finding.reason||finding.category}`,severity);diagnostic.source='Guardian';issues.push(diagnostic);
        }
        if(scan.recommendation!=='accept' && !issues.length)issues.push(new vscode.Diagnostic(document.lineAt(0).range,scan.explanation,vscode.DiagnosticSeverity.Warning));
        diagnostics.set(document.uri,issues);output.appendLine(`${scan.request_id}: ${scan.recommendation} ${scan.trust_score}/100\n${scan.explanation}`);
        vscode.window.showInformationMessage(`Guardian: ${scan.recommendation.toUpperCase()} · ${scan.trust_score}/100`);
      }catch(error){if(document.isClosed||generations.get(id)!==generation)return;diagnostics.set(document.uri,[new vscode.Diagnostic(document.lineAt(0).range,'Guardian scan unavailable or incomplete; review required.',vscode.DiagnosticSeverity.Warning)]);vscode.window.showWarningMessage('Guardian: '+String(error));}
      finally{subscription.dispose();if(activeControllers.get(id)===controller)activeControllers.delete(id);}
    });
  }
  context.subscriptions.push(diagnostics,output,vscode.commands.registerCommand('guardian.scanActive',async()=>{
    const editor=vscode.window.activeTextEditor;if(editor)await scanDocument(editor.document);
  }));
  context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(document=>{
    if(document.uri.scheme!=='file'||!vscode.workspace.getConfiguration('guardian',document.uri).get('scanOnSave',false))return;
    const id=document.uri.toString();clearTimeout(saveTimers.get(id));
    saveTimers.set(id,setTimeout(()=>{saveTimers.delete(id);if(!document.isClosed)void scanDocument(document);},300));
  }),vscode.workspace.onDidCloseTextDocument(document=>{
    const id=document.uri.toString();clearTimeout(saveTimers.get(id));saveTimers.delete(id);activeControllers.get(id)?.abort();activeControllers.delete(id);generations.delete(id);diagnostics.delete(document.uri);
  }),{dispose:cancelScans});
}
export function deactivate() {}
