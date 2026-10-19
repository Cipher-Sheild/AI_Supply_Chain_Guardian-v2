import { FormEvent, useEffect, useRef, useState } from 'react';

type Finding = { category: string; severity: string; confidence: number; location?: string; reason?: string; remediation?: string };
type Agent = { agent_name: string; status: string; coverage: string; findings: Finding[]; evidence?: Record<string, unknown> };
type Scoring = { method: string; model_version?: string; training_scope?: string; reason?: string; shap?: { base_value: number; agent_contributions: Record<string, number>; agent_selected?: Record<string, boolean>; output_space: string } };
type Scan = { scoring?: Scoring; request_id: string; trust_score: number; recommendation: string; scan_status: string; explanation: string; detector_results: Agent[]; per_file?: { filename: string; trust_score: number; recommendation: string; coverage: string }[]; routing?: { overall_coverage: string } };
type ComparisonResult = { scan_id?: string; score?: number; recommendation?: string; method?: string; decision: string; reason?: string };
type Comparison = { timestamp?: string; run?: string; filenames?: string[]; relative_filenames?: string[]; weighted: ComparisonResult; ml: ComparisonResult };
type FileInput = { filename: string; content: string };
let sessionApiKey = '';
let sessionGeneration = 0;
let importGeneration = 0;
function requestHeaders(body?: unknown): Record<string,string> {
  const headers: Record<string,string> = {};
  if(body) headers['Content-Type']='application/json';
  if(sessionApiKey) headers['Authorization']='Bearer '+sessionApiKey;
  return headers;
}
async function api<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch('/api' + path, {redirect:'error',method:body?'POST':'GET',headers:requestHeaders(body),body:body?JSON.stringify(body):undefined});
  if (!response.ok) throw new Error(response.status===401 ? 'Connect your deployment to view scans and export reports.' : `Request failed (HTTP ${response.status}). Please retry.`);
  return response.json();
}
export default function App() {
  const [connected,setConnected]=useState(false);
  const [comparisons,setComparisons]=useState<Comparison[]>([]);
  const [comparisonEnabled,setComparisonEnabled]=useState(false);
  const [comparisonError,setComparisonError]=useState('');
  const [selectedRun,setSelectedRun]=useState('');
  const [localAccess,setLocalAccess]=useState(false);
  const [historyBusy,setHistoryBusy]=useState(false);
  const [opening,setOpening]=useState('');
  const [exporting,setExporting]=useState('');
  const [notice,setNotice]=useState('');
  const historySequence=useRef(0);
  const selectionSequence=useRef(0);
  const [apiKey, setApiKey] = useState('');
  const [filename, setFilename] = useState('artifact.py');
  const [containerScope,setContainerScope]=useState('resolved_images');
  const [content, setContent] = useState('');
  const [files, setFiles] = useState<FileInput[]>([]);
  const [scan, setScan] = useState<Scan>();
  const [history, setHistory] = useState<Scan[]>([]);
  const [offset, setOffset] = useState(0);
  const [pageSize,setPageSize]=useState(10);
  const [totals,setTotals]=useState<{total:number;attention:number}>();
  const [comparisonPageSize,setComparisonPageSize]=useState(10);
  const [comparisonPage,setComparisonPage]=useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  function useSessionKey(key:string) {
    if(window.location.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(window.location.hostname))throw new Error('HTTPS is required for remote deployment access.');
    sessionApiKey=key;setConnected(true);sessionGeneration++;importGeneration++;setScan(undefined);setHistory([]);setOffset(0);setApiKey('');setError('');void refresh(0);
  }
  async function refresh(page = offset) {
    const generation=sessionGeneration,sequence=++historySequence.current;setHistoryBusy(true);
    try { const data = await api<{ items: Scan[]; has_more: boolean }>(`/scans?limit=${pageSize}&offset=${page}`); if(generation!==sessionGeneration||sequence!==historySequence.current)return; setError('');setConnected(true);setHistory(data.items); setHasMore(data.has_more); }
    catch (e) { if(generation===sessionGeneration&&sequence===historySequence.current){setError(String(e));if(e instanceof Error&&e.message.startsWith('Connect your deployment'))setConnected(false);} }
    finally {if(sequence===historySequence.current)setHistoryBusy(false);}
  }
  useEffect(()=>{let active=true;void fetch('/api/connection').then(r=>r.ok?r.json():{local_access:false}).then(data=>{if(active&&data.local_access){setLocalAccess(true);setConnected(true);void refresh(0);}}).catch(()=>{});return()=>{active=false;};},[]);
  useEffect(() => { if(connected)void refresh(offset); }, [offset,connected,pageSize]);
  useEffect(()=>{
    if(!connected)return;
    let active=true,inFlight=false;
    const update=async()=>{if(inFlight)return;inFlight=true;try{
      const summary=await api<{total:number;attention:number}>('/history-summary');if(active)setTotals(summary);
    }catch{if(active)setTotals(undefined);}finally{inFlight=false;}};
    void update();const timer=window.setInterval(()=>{if(!document.hidden)void update();},5000);
    return()=>{active=false;window.clearInterval(timer);};
  },[connected]);

  useEffect(()=>{
    if(!localAccess||!connected)return;
    let active=true;
    const update=async()=>{try{
      const response=await fetch('/api/comparison-runs',{cache:'no-store'});
      if(!response.ok)throw Error('Comparison history unavailable.');
      const data=await response.json();
      if(active){setComparisonEnabled(!!data.enabled);setComparisons(Array.isArray(data.items)?data.items:[]);setComparisonError('');}
    }catch{if(active)setComparisonError('Comparison history is temporarily unavailable.');}};
    void update();const timer=window.setInterval(()=>{if(!document.hidden)void update();},5000);
    return()=>{active=false;window.clearInterval(timer);};
  },[localAccess,connected]);
  useEffect(()=>{
    if(!connected)return;
    const id=new URLSearchParams(window.location.search).get('scan');
    if(id&&/^[a-f0-9]{32}$/.test(id))void loadScan(id);
  },[connected]);

  useEffect(()=>{if(!connected||offset!==0)return;const timer=window.setInterval(()=>{if(!document.hidden)void refresh(0);},5000);return()=>window.clearInterval(timer);},[connected,offset,pageSize]);
  useEffect(() => {
    if (scan?.scan_status !== 'provisional') return;
    let active = true;
    let inFlight = false;
    const requestId = scan.request_id;
    const generation=sessionGeneration;
    const timer = window.setInterval(async () => {
      if (!active || inFlight) return;
      inFlight = true;
      try {
        const updated = await api<Scan>(`/scans/${requestId}`);
        if (active && generation===sessionGeneration) { setScan(updated); setError(''); if (updated.scan_status === 'final') void refresh(); }
      } catch (e) { if (active && generation===sessionGeneration) setError(String(e)); }
      finally { inFlight = false; }
    }, 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, [scan?.request_id, scan?.scan_status]);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    const generation=sessionGeneration;
    try { const result=await api<Scan>('/analyze/batch', { files: (files.length ? files : [{ filename, content }]).map(file=>({...file,options:{scan_scope:containerScope}})) }); if(generation!==sessionGeneration)return;setScan(result); void refresh(); }
    catch (e) { if(generation===sessionGeneration)setError(String(e)); } finally { setBusy(false); }
  }
  async function loadScan(requestId:string) {
    const generation=sessionGeneration,sequence=++selectionSequence.current;setOpening(requestId);setError('');
    try { const result=await api<Scan>(`/scans/${requestId}`);if(generation===sessionGeneration&&sequence===selectionSequence.current){setScan(result);setNotice('');} }
    catch(e) { if(generation===sessionGeneration&&sequence===selectionSequence.current)setError(String(e)); }
    finally{if(sequence===selectionSequence.current)setOpening('');}
  }
  async function downloadPdf(requestId:string){
    const generation=sessionGeneration;setExporting(requestId);setError('');setNotice('');
    try{
      const response=await fetch(`/api/scans/${encodeURIComponent(requestId)}/audit.pdf`,{redirect:'error',headers:requestHeaders()});
      if(!response.ok)throw new Error(response.status===401?'Connect your deployment before exporting a report.':`PDF export failed (HTTP ${response.status}). Please retry.`);
      const blob=await response.blob();
      if((await blob.slice(0,5).text())!=='%PDF-')throw new Error('The server did not return a valid PDF. Please retry.');
      if(generation!==sessionGeneration)return;
      const url=URL.createObjectURL(blob),link=document.createElement('a');
      link.href=url;link.download=`guardian-${requestId}.pdf`;document.body.appendChild(link);link.click();link.remove();
      window.setTimeout(()=>URL.revokeObjectURL(url),60000);
      setNotice(`Report downloaded: guardian-${requestId}.pdf. Check your browser’s Downloads folder.`);
    }catch(err){if(generation===sessionGeneration)setError(String(err));}
    finally{setExporting('');}
  }
  function clearAccess(){sessionApiKey='';sessionGeneration++;importGeneration++;historySequence.current++;selectionSequence.current++;setConnected(false);setHistory([]);setScan(undefined);setApiKey('');setHasMore(false);setOffset(0);setHistoryBusy(false);setNotice('');setError('');}
  const findings=scan?.detector_results.reduce((n,a)=>n+a.findings.length,0)||0;
  const pairFor=(id:string)=>comparisons.find(pair=>pair.weighted.scan_id===id||pair.ml.scan_id===id);
  const artifactName=(item:Scan)=>pairFor(item.request_id)?.filenames?.map(path=>path.split('/').pop()).join(', ')||item.per_file?.[0]?.filename?.split('/').pop()||item.detector_results?.flatMap(a=>a.findings).find(f=>f.location)?.location?.replace(/:\d+$/,'').split('/').pop()||'Artifact scan';
  const runs=Array.from(new Set(comparisons.map(pair=>pair.run).filter(Boolean))) as string[];
  const filteredPairs=comparisons.filter(pair=>!selectedRun||pair.run===selectedRun).slice().reverse();
  const shownPairs=filteredPairs.slice(comparisonPage*comparisonPageSize,(comparisonPage+1)*comparisonPageSize);
  const pretty=(name:string)=>name.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());
  return <div className="shell">
    <aside className="sidebar"><a className="brand" href="#"><span className="brand-mark">G</span><span>Guardian<small>SUPPLY CHAIN SECURITY</small></span></a>
      <div className="nav-label">WORKSPACE</div><a className="nav-item active" href="#history">◈ <span>Security overview</span></a><a className="nav-item" href="#new-scan">＋ <span>Review an artifact</span></a><a className="nav-item" href="#report">▤ <span>Evidence & reports</span></a>
      <div className="sidebar-note"><span className="live-dot"/>PRE-ACCEPTANCE REVIEW<p>Inspect the proposal.<br/>Understand the evidence.<br/>Decide with confidence.</p></div><div className="sidebar-footer">AI Supply Chain Guardian<br/><span>Local analyst workspace</span></div>
    </aside>
    <main><div className="topbar"><span>Workspace <span className="slash">/</span> Security overview</span><span className={'connection '+(connected?'online':'')}><i/>{connected?'Deployment connected':'Connection required'}</span></div>
    <header><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Your supply chain.<br/><span>Under review.</span></h1><p>From proposed code to a decision you can explain. All your scans, evidence, and audit reports in one place.</p></div><a className="button primary" href="#new-scan">＋ New artifact scan</a></header>
    <div className="metrics"><div><span>TOTAL SAVED SCANS</span><strong>{totals?.total??'—'}</strong><small>Across all history pages</small></div><div><span>REQUIRE ATTENTION</span><strong>{totals?.attention??'—'}</strong><small>Review or rejection decisions</small></div><div><span>DETECTOR SERVICES</span><strong>07</strong><small>Selected by artifact type</small></div><div><span>REPORT EXPORT</span><strong className="text-metric">PDF audit</strong><small>Available for each saved scan</small></div></div>
    {!localAccess&&<details className="access-panel"><summary>Deployment access <span>{connected?'Session key connected':'Connect to view history and download reports'}</span></summary><form onSubmit={event=>{event.preventDefault();try{if(!apiKey.trim())throw Error('Enter a client API key or import your deployment configuration.');useSessionKey(apiKey.trim());}catch(e){setError(String(e));}}}>
      <label>API key<input type="password" autoComplete="off" value={apiKey} onChange={event=>setApiKey(event.target.value)}/></label><div className="actions"><button>Use key for this session</button><button className="secondary" type="button" onClick={clearAccess}>Clear key</button></div>
      <label className="file-upload">Import deployment client key<input type="file" onChange={async event=>{const input=event.currentTarget,file=input.files?.[0];if(!file)return;const ticket=++importGeneration,generation=sessionGeneration;try{if(file.size>65536)throw Error('Deployment configuration exceeds 64 KiB.');const text=await file.text(),keys=text.split(/\r?\n/).filter(line=>line.startsWith('GUARDIAN_API_KEY=')).map(line=>line.slice(17).trim());if(ticket!==importGeneration||generation!==sessionGeneration)return;if(keys.length!==1||!keys[0]||/[\s"']/.test(keys[0]))throw Error('Select a configuration containing one client API key.');useSessionKey(keys[0]);}catch(e){setError(String(e));}finally{input.value='';}}}/></label><p className="muted">Your key stays in memory and clears on reload. Use HTTPS for remote deployments.</p></form></details>}
    {localAccess&&<div className="local-banner"><span className="live-dot"/> Local deployment access is ready. Credentials stay on the local proxy, outside your browser.</div>}
    {error&&<p role="alert" className="error">{error}</p>}{notice&&<p role="status" className="success">{notice}</p>}
    {comparisonEnabled&&<section className="panel comparison-panel" id="comparison"><div className="panel-heading"><div><p className="eyebrow">COPILOT PROPOSAL COMPARISON</p><h2>Weighted and ML, paired by proposal</h2><p>Both results below belong to the same proposed content. Weighted controls writes; ML is advisory. Live detector evidence can differ.</p></div></div>
      <div className="comparison-toolbar"><label className="comparison-filter">Run folder<select aria-label="Run folder" value={selectedRun} onChange={e=>{setSelectedRun(e.target.value);setComparisonPage(0);}}><option value="">All recent proposals ({comparisons.length})</option>{runs.map(run=><option key={run} value={run}>{run}</option>)}</select></label><label className="page-size">Rows per page<select aria-label="Comparison rows per page" value={comparisonPageSize} onChange={e=>{setComparisonPageSize(Number(e.target.value));setComparisonPage(0);}}>{[10,20,50,100].map(n=><option key={n} value={n}>{n}</option>)}</select></label><span className="proposal-count">{filteredPairs.length} proposals</span></div>
      {comparisonError&&<p role="alert">{comparisonError}</p>}
      <div className="table-scroll"><table className="comparison-table"><thead><tr><th>RUN / FILE / TIME</th><th>WEIGHTED · 3000</th><th>ML / SHAP · 3302</th><th>WRITE GATE</th></tr></thead><tbody>{shownPairs.map((pair,index)=><tr key={pair.weighted.scan_id||pair.ml.scan_id||index}><td className="proposal-identity"><b>{pair.run||'Unidentified proposal'}</b><div>{pair.filenames?.map((path,i)=><div key={path} title={path}>{pair.relative_filenames?.[i]||path}</div>)||'Unsupported proposal; no artifact scan'}</div><small>{pair.timestamp?new Date(pair.timestamp).toLocaleString():'Time not recorded'}</small></td>{(['weighted','ml'] as const).map(mode=>{const result=pair[mode];return <td key={mode} className="comparison-result"><b className="comparison-score">{result.score!==undefined?`${result.score.toFixed(2)} / 100 · ${result.recommendation}`:result.scan_id?'Scan recorded; open report':'No completed hook result'}</b><span className="method-tag">{result.method||'Inspection unavailable'}</span>{result.scan_id&&<a href={`http://127.0.0.1:${mode==='weighted'?3000:3302}/?scan=${result.scan_id}`} target="_blank" rel="noreferrer">Open {mode} report ↗</a>}<details><summary>View hook details</summary><small>{result.scan_id||'No scan ID returned'}</small><p>{result.reason}</p></details></td>})}<td><span className={'badge '+(pair.weighted.decision==='allow'?'accept':'reject')}>{pair.weighted.decision==='allow'?'Write allowed':'Write denied'}</span></td></tr>)}</tbody></table></div>
      {!filteredPairs.length&&<div className="empty"><span>◎</span><h3>Ready for a fresh comparison</h3><p>Submit a proposal in Copilot. Its weighted and ML results will appear together here.</p></div>}
      <div className="pagination comparison-pagination"><span>{filteredPairs.length?comparisonPage*comparisonPageSize+1:0}–{Math.min((comparisonPage+1)*comparisonPageSize,filteredPairs.length)} of {filteredPairs.length} proposals</span><div><button className="secondary" disabled={!comparisonPage} onClick={()=>setComparisonPage(comparisonPage-1)}>Previous proposals</button><button className="secondary" disabled={(comparisonPage+1)*comparisonPageSize>=filteredPairs.length} onClick={()=>setComparisonPage(comparisonPage+1)}>Next proposals</button></div></div>
      <p className="comparison-note">This table shows the last 1,000 comparison hook records, including errors. The run filter applies to this table only. Missing IDs and timeouts are not successful scans. Saved scans remain in history until deleted or removed by retention policy.</p>
    </section>}
    <section id="history" className="panel"><div className="panel-heading"><div><p className="eyebrow">LIVE ACTIVITY</p><h2>Scan history</h2><p>VS Code, CLI, and website scans appear here. Updates every 5 seconds on the first page. Choose how many rows to display. Older saved scans remain available with Next.</p></div><button className="secondary" disabled={!connected||historyBusy} onClick={()=>void refresh()}>{historyBusy?'Refreshing…':'Refresh history'}</button></div>
      {!connected?<div className="empty"><span>◎</span><h3>Connect your deployment</h3><p>Import your client configuration above to load scan history and enable PDF exports.</p></div>:!history.length?<div className="empty"><span>◎</span><h3>{historyBusy?'Loading your scans…':'Ready for your first scan'}</h3><p>Propose an artifact in VS Code or submit one below. Its report will appear here.</p></div>:<div className="table-scroll"><table className="history-table"><thead><tr><th>SCAN / ARTIFACT</th><th>DECISION</th><th>TRUST SCORE</th><th>STATUS</th><th>REPORT</th></tr></thead><tbody>{history.map(item=><tr key={item.request_id} className={scan?.request_id===item.request_id?'selected':''}><td><button className="scan-link" disabled={!!opening} onClick={()=>void loadScan(item.request_id)}>{artifactName(item)}<small>{pairFor(item.request_id)?.run||'Saved deployment scan'} · {pairFor(item.request_id)?.timestamp?new Date(pairFor(item.request_id)!.timestamp!).toLocaleString():''}</small><small title={item.request_id}>{item.request_id} · Open report →</small></button></td><td><span className={'badge '+item.recommendation}>{item.recommendation}</span></td><td><b>{item.trust_score.toFixed(2)}</b><span className="muted"> / 100</span></td><td><span className="status-dot"/>{item.scan_status}</td><td><button className="pdf-button" disabled={!!exporting} onClick={()=>void downloadPdf(item.request_id)}>{exporting===item.request_id?'Exporting…':'Download PDF ↓'}</button></td></tr>)}</tbody></table></div>}
      <div className="pagination"><label className="page-size">Rows per page<select aria-label="History rows per page" value={pageSize} onChange={e=>{setPageSize(Number(e.target.value));setOffset(0);}}>{[10,20,50,100].map(n=><option key={n} value={n}>{n}</option>)}</select></label><span>{opening?'Opening scan…':`Showing ${history.length?offset+1:0}–${offset+history.length}${totals?` of ${totals.total} saved scans`:''}`}</span><div><button className="secondary" disabled={!offset||historyBusy} onClick={()=>setOffset(Math.max(0,offset-pageSize))}>Previous</button><button className="secondary" disabled={!hasMore||historyBusy} onClick={()=>setOffset(offset+pageSize)}>Next</button></div></div>
    </section>
    <div id="report">{scan?<section className="panel report-panel" aria-live="polite"><div className="panel-heading"><div><p className="eyebrow">SCAN ANALYSIS · {scan.request_id.slice(0,12)}</p><h2>Evidence behind the decision</h2></div><button disabled={!!exporting} onClick={()=>void downloadPdf(scan.request_id)}>{exporting===scan.request_id?'Generating report…':'Download audit PDF'}</button></div>
      <div className={'verdict '+scan.recommendation}><div><span className="eyebrow">GUARDIAN DECISION</span><h2>{scan.recommendation.toUpperCase()}</h2><span>{scan.scan_status==='provisional'?'Provisional · waiting for judge':'Final'}</span></div><div className="score"><strong>{scan.trust_score.toFixed(2)}</strong><span>/ 100 trust score</span></div><div><b>{findings} findings</b><p>{scan.routing?.overall_coverage||'See per-file'} coverage</p></div></div><p className="explanation">{scan.explanation}</p>
      {scan.per_file?.map((file,i)=><div className="file-result" key={i}><code>{file.filename}</code><span className={'badge '+file.recommendation}>{file.recommendation}</span><span>{file.trust_score.toFixed(2)} / 100 · {file.coverage} coverage</span></div>)}
      <h3 className="section-title">Detector evidence <span>{scan.detector_results.length} results</span></h3>{scan.detector_results.map((agent,i)=><details className="agent" key={i} open={agent.findings.length>0}><summary><span>{pretty(agent.agent_name)}</span><span className={'badge '+(agent.status==='pass'?'accept':agent.status==='fail'?'reject':'review')}>{agent.status}</span><small>{agent.coverage} coverage · {agent.findings.length} findings</small></summary>{typeof agent.evidence?.scan_scope==='string'&&<p className="scope-notice"><b>Scan scope: {agent.evidence.scan_scope.replace(/_/g,' ')}</b><br/>{String(agent.evidence.scope_notice||'')}</p>}{agent.findings.map((finding,j)=><article key={j}><b>{finding.severity} · {finding.category}</b><p>{finding.reason}</p><code>{finding.location}</code>{finding.remediation&&<p className="remediation">{finding.remediation}</p>}</article>)}<details className="raw-evidence"><summary>Detector evidence</summary><pre>{JSON.stringify(agent.evidence||{},null,2)}</pre></details></details>)}
      {scan.scoring&&<div className="scoring"><p className="eyebrow">TRUST ENGINE</p><h3>Scoring: {scan.scoring.method}</h3>{scan.scoring.model_version&&<p>Model: {scan.scoring.model_version} · {scan.scoring.training_scope}</p>}{scan.scoring.reason&&<p>Weighted fallback: {scan.scoring.reason}</p>}{scan.scoring.shap&&<><p>TreeSHAP baseline: {scan.scoring.shap.base_value.toFixed(2)} trust points. Contributions explain the model score before safety gates.</p><table><thead><tr><th>Detector</th><th>Contribution</th></tr></thead><tbody>{Object.entries(scan.scoring.shap.agent_contributions).map(([name,value])=><tr key={name}><td>{pretty(name)}{scan.scoring?.shap?.agent_selected?.[name]===false?' (not selected; missingness contribution)':''}</td><td>{value>=0?'+':''}{value.toFixed(3)}</td></tr>)}</tbody></table></>}<p className="muted">Hard overrides and uncertainty floors remain authoritative. Model explanations are not causal evidence.</p></div>}
    </section>:<div className="report-hint">↗ Select a scan above to explore findings, coverage, and scoring. You can download its PDF directly from history.</div>}</div>
    <section id="new-scan" className="panel"><div className="panel-heading"><div><p className="eyebrow">ARTIFACT REVIEW</p><h2>Inspect before you accept</h2><p>Paste a proposal or upload source and configuration files.</p></div><span className="badge neutral">Up to 50 files</span></div><form onSubmit={submit}><label>Filename<input value={filename} onChange={e=>setFilename(e.target.value)} required/></label><label>Artifact content<textarea value={content} onChange={e=>setContent(e.target.value)} rows={8} spellCheck={false} placeholder="Paste proposed code or configuration here…"/></label><label>Container scan scope<select value={containerScope} onChange={e=>setContainerScope(e.target.value)}><option value="resolved_images">Configuration and resolved images (default)</option><option value="supplied_text">Supplied configuration only</option></select><small>Applies to Dockerfiles and Compose. Configuration-only scans do not inspect image contents or CVEs.</small></label><label className="file-upload">Or select files (50 maximum, 256 KiB each)<input type="file" multiple onChange={async e=>{try{const selected=Array.from(e.target.files||[]);if(selected.length>50||selected.some(f=>f.size>262144)||selected.reduce((n,f)=>n+f.size,0)>1048576)throw Error('Upload exceeds file or batch limits.');setFiles(await Promise.all(selected.map(async f=>({filename:f.name,content:await f.text()}))));setError('');}catch(err){setFiles([]);setError(String(err));}}}/></label>{files.length>0&&<p>{files.map(f=>f.filename).join(', ')} <button type="button" className="secondary" onClick={()=>setFiles([])}>Clear files</button></p>}<div className="form-footer"><p>Only relevant detectors run for each artifact type.</p><button disabled={!connected||busy||(!files.length&&!content.trim())}>{busy?'Scanning…':'Scan artifacts'}</button></div></form></section>
    <footer><b>Guardian</b><span>Evidence first. Every decision traceable.</span><p>Weighted baseline with optional synthetic-trained XGBoost and TreeSHAP. Partial coverage requires review; model quality depends on independent validation.</p></footer>
    </main></div>;
}
