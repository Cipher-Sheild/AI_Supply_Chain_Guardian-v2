import { FormEvent, useEffect, useState } from 'react';

type Finding = { category: string; severity: string; confidence: number; location?: string; reason?: string; remediation?: string };
type Agent = { agent_name: string; status: string; coverage: string; findings: Finding[]; evidence?: Record<string, unknown> };
type Scoring = { method: string; model_version?: string; training_scope?: string; reason?: string; shap?: { base_value: number; agent_contributions: Record<string, number>; agent_selected?: Record<string, boolean>; output_space: string } };
type Scan = { scoring?: Scoring; request_id: string; trust_score: number; recommendation: string; scan_status: string; explanation: string; detector_results: Agent[]; per_file?: { filename: string; trust_score: number; recommendation: string; coverage: string }[]; routing?: { overall_coverage: string } };
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
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  return response.json();
}
export default function App() {
  const [apiKey, setApiKey] = useState('');
  const [filename, setFilename] = useState('artifact.py');
  const [content, setContent] = useState('');
  const [files, setFiles] = useState<FileInput[]>([]);
  const [scan, setScan] = useState<Scan>();
  const [history, setHistory] = useState<Scan[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  function useSessionKey(key:string) {
    if(window.location.protocol!=='https:'&&!['localhost','127.0.0.1','[::1]'].includes(window.location.hostname))throw new Error('HTTPS is required for remote deployment access.');
    sessionApiKey=key;sessionGeneration++;importGeneration++;setScan(undefined);setHistory([]);setOffset(0);setApiKey('');setError('');void refresh(0);
  }
  async function refresh(page = offset) {
    const generation=sessionGeneration;
    try { const data = await api<{ items: Scan[]; has_more: boolean }>(`/scans?limit=10&offset=${page}`); if(generation!==sessionGeneration)return; setHistory(data.items); setHasMore(data.has_more); }
    catch (e) { if(generation===sessionGeneration)setError(String(e)); }
  }
  useEffect(() => { void refresh(offset); }, [offset]);
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
    try { const result=await api<Scan>('/analyze/batch', { files: files.length ? files : [{ filename, content }] }); if(generation!==sessionGeneration)return;setScan(result); void refresh(); }
    catch (e) { if(generation===sessionGeneration)setError(String(e)); } finally { setBusy(false); }
  }
  async function loadScan(requestId:string) {
    const generation=sessionGeneration;
    try { const result=await api<Scan>(`/scans/${requestId}`);if(generation===sessionGeneration)setScan(result); }
    catch(e) { if(generation===sessionGeneration)setError(String(e)); }
  }
  return <main>
    <header><p className="eyebrow">PTIC · supply chain review</p><h1>AI Supply Chain Guardian</h1><p>Scan an artifact before you accept it. Inspect the evidence and coverage behind its decision.</p></header>
    <details><summary>Deployment access</summary><form onSubmit={event=>{event.preventDefault();
      try{useSessionKey(apiKey);}catch(error){setError(String(error));}}}>
      <label>API key<input type="password" autoComplete="off" value={apiKey} onChange={event=>setApiKey(event.target.value)} /></label>
      <button>Use key for this session</button><button type="button" onClick={()=>{sessionApiKey='';sessionGeneration++;importGeneration++;setHistory([]);setScan(undefined);setApiKey('');setHasMore(false);setOffset(0);}}>Clear key</button>
      <label>Import deployment client key<input type="file" onChange={async event=>{
        const input=event.currentTarget;const file=input.files?.[0];if(!file)return;
        const ticket=++importGeneration;const generation=sessionGeneration;
        try{
          if(file.size>65536)throw new Error('Deployment configuration exceeds 64 KiB.');
          const text=await file.text();const keys=text.split(/\r?\n/).filter(line=>line.startsWith('GUARDIAN_API_KEY=')).map(line=>line.slice('GUARDIAN_API_KEY='.length).trim());
          if(ticket!==importGeneration||generation!==sessionGeneration)return;
          if(keys.length!==1||!keys[0]||/[\s"']/.test(keys[0]))throw new Error('Select a Guardian deployment configuration with one client key.');
          useSessionKey(keys[0]);
        }catch(error){setError(String(error));}finally{input.value='';}
      }}/></label>
      <p>The key stays in memory and is cleared when this page reloads. Use HTTPS for remote deployments.</p>
    </form></details>
    <form onSubmit={submit}>
      <label>Filename<input value={filename} onChange={e => setFilename(e.target.value)} required /></label>
      <label>Artifact content<textarea value={content} onChange={e => setContent(e.target.value)} rows={10} spellCheck={false} /></label>
      <label>Or select files (50 maximum, 256 KiB each)<input type="file" multiple onChange={async e => {
        try { const selected = Array.from(e.target.files || []); if (selected.length > 50 || selected.some(f => f.size > 262144) || selected.reduce((n,f) => n+f.size,0)>1048576) throw new Error('Upload exceeds file or batch limits.'); setFiles(await Promise.all(selected.map(async f => ({ filename: f.name, content: await f.text() })))); setError(''); } catch (err) { setFiles([]); setError(String(err)); }
      }} /></label>
      {files.length > 0 && <p>{files.map(f => f.filename).join(', ')} <button type="button" onClick={() => setFiles([])}>Clear files</button></p>}
      <button disabled={busy || (!files.length && !content.trim())}>{busy ? 'Scanning…' : 'Scan artifacts'}</button>
    </form>
    {error && <p role="alert" className="error">{error}</p>}
    {scan && <section aria-live="polite"><div className="verdict"><h2>{scan.recommendation.toUpperCase()}</h2><strong>{scan.trust_score.toFixed(2)} / 100</strong><span>{scan.scan_status === 'provisional' ? 'Provisional · waiting for judge' : 'Final'}</span></div>
      <p>{scan.explanation}</p><p>Coverage: {scan.routing?.overall_coverage || 'See per-file coverage'}</p>
      {scan.scoring && <section><h3>Scoring: {scan.scoring.method}</h3>
        {scan.scoring.model_version && <p>Model: {scan.scoring.model_version} · {scan.scoring.training_scope}</p>}
        {scan.scoring.reason && <p>Weighted fallback: {scan.scoring.reason}</p>}
        {scan.scoring.shap && <><p>TreeSHAP baseline: {scan.scoring.shap.base_value.toFixed(2)} trust points. Contributions explain the model score before safety gates.</p>
          <table><thead><tr><th>Detector</th><th>Contribution</th></tr></thead><tbody>{Object.entries(scan.scoring.shap.agent_contributions).map(([name, value]) => <tr key={name}><td>{name}{scan.scoring?.shap?.agent_selected?.[name] === false ? " (not selected; missingness contribution)" : ""}</td><td>{value >= 0 ? '+' : ''}{value.toFixed(3)}</td></tr>)}</tbody></table></>}
        <p>Hard overrides and uncertainty floors remain authoritative. Model explanations are not causal evidence.</p>
      </section>}
      <button onClick={async()=>{try{
        const response=await fetch(`/api/scans/${scan.request_id}/audit.pdf`,{redirect:'error',headers:requestHeaders()});
        if(!response.ok)throw new Error(`HTTP ${response.status}`);
        const url=URL.createObjectURL(await response.blob());const link=document.createElement('a');link.href=url;link.download=`guardian-${scan.request_id}.pdf`;link.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);
      }catch(err){setError(String(err));}}}>Download audit PDF</button>
      {scan.per_file?.map((file, i) => <p key={i}><b>{file.filename}</b> · {file.recommendation} · {file.trust_score.toFixed(2)} · {file.coverage} coverage</p>)}
      {scan.detector_results.map((agent, i) => <details key={i} open={agent.findings.length > 0}><summary>{agent.agent_name} · {agent.status} · {agent.coverage} coverage</summary>
        {agent.findings.map((finding, j) => <article key={j}><b>{finding.severity} · {finding.category}</b><p>{finding.location} {finding.reason}</p><p>{finding.remediation}</p></article>)}
        <details><summary>Detector evidence</summary><pre>{JSON.stringify(agent.evidence, null, 2)}</pre></details>
      </details>)}
    </section>}
    <section><h2>Scan history</h2><button onClick={() => void refresh()}>Refresh history</button><ul>{history.map(item => <li key={item.request_id}><button onClick={() => void loadScan(item.request_id)}>{item.request_id.slice(0, 12)} · {item.recommendation} · {item.trust_score.toFixed(2)} · {item.scan_status}</button></li>)}</ul>
      <button disabled={!offset} onClick={() => setOffset(Math.max(0, offset-10))}>Previous</button> <button disabled={!hasMore} onClick={() => setOffset(offset+10)}>Next</button>
    </section><footer>Weighted baseline with optional synthetic-trained XGBoost and TreeSHAP. Partial coverage requires review; model quality depends on independent validation.</footer>
  </main>;
}
