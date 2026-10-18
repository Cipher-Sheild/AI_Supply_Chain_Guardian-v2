"""Public batch bounds, per-file outcomes and audit export."""
from io import BytesIO
from functools import lru_cache
from xml.sax.saxutils import escape
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.schemas import ArtifactRequest
from app.pending_store import get_store
from app.state import ScanResponse, achieved_coverage
from app.fusion import fuse
from app.orchestration import _compiled_graph

@lru_cache(maxsize=1)
def _report_fonts():
    from pathlib import Path
    import reportlab
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    root=Path(reportlab.__file__).parent/'fonts'
    pdfmetrics.registerFont(TTFont('GuardianSans',str(root/'Vera.ttf')))
    pdfmetrics.registerFont(TTFont('GuardianSansBold',str(root/'VeraBd.ttf')))
    return 'GuardianSans','GuardianSansBold'

MAX_FILE_BYTES=262144
MAX_TOTAL_BYTES=1048576
class BatchRequest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    files:list[ArtifactRequest]=Field(min_length=1,max_length=50)
    @model_validator(mode='after')
    def bounds(self):
        total=0;names=set()
        for artifact in self.files:
            name=artifact.filename or artifact.file_path
            if not name or len(name)>512: raise ValueError('batch files require a filename of at most 512 characters')
            canonical=name.replace('\\','/').strip()
            if canonical in names: raise ValueError('batch filenames must be unique')
            names.add(canonical)
            size=len(artifact.content.encode('utf-8'));total+=size
            if size>MAX_FILE_BYTES: raise ValueError('file exceeds 256 KiB work limit')
        if total>MAX_TOTAL_BYTES: raise ValueError('batch exceeds 1 MiB content work limit')
        return self

def per_file_outcomes(state):
    output=[]
    for i,(file,decision) in enumerate(zip(state.get('files',[]),state.get('routing',[]))):
        subset={**state,'files':[file],'routing':[decision],
            'results':[r for r in state.get('results',[]) if r.file==decision.filename],
            'pending_callbacks':[p for p in state.get('pending_callbacks',[]) if p.file==decision.filename]}
        result=fuse(subset).model_dump()
        output.append({'index':i,'filename':decision.filename,'coverage':achieved_coverage(subset),
            'scan_status':'provisional' if subset['pending_callbacks'] else 'final','scoring':subset.get('scoring',{}),**result})
    return output

router=APIRouter()
@router.post('/analyze/batch',response_model=ScanResponse)
async def analyze_batch(body:BatchRequest,store=Depends(get_store)):
    from app.main import save_state
    files=[]
    for artifact in body.files:
        data=artifact.model_dump(exclude_none=True)
        data['filename']=artifact.filename or artifact.file_path
        files.append(data)
    state=await _compiled_graph.ainvoke({'files':files,'routing':[],'results':[],
        'pending_callbacks':[],'routing_notes':[],'trust_result':{}})
    return await save_state(state,store)

@router.get('/scans/{request_id}/audit.pdf')
async def audit_pdf(request_id:str,store=Depends(get_store)):
    from app.main import get_scan
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.pagesizes import A4
    result=await get_scan(request_id,store)
    data=result.model_dump(mode='json')
    stream=BytesIO();styles=getSampleStyleSheet();story=[]
    regular,bold=_report_fonts()
    styles['BodyText'].fontName=regular;styles['BodyText'].fontSize=10;styles['BodyText'].leading=14
    styles['Title'].fontName=bold;styles['Title'].fontSize=20;styles['Title'].leading=24
    styles['Heading2'].fontName=bold;styles['Heading2'].fontSize=12;styles['Heading2'].leading=16
    def line(text,style='BodyText'):
        # ReportLab markup must not interpret user-supplied findings as tags.
        story.append(Paragraph(escape(str(text)),styles[style]));story.append(Spacer(1,8))
    line('AI Supply Chain Guardian audit','Title')
    line('Request: '+request_id)
    line(f"Status: {data['scan_status']} | Score: {data['trust_score']:.2f} | Decision: {data['recommendation']}")
    line(data.get('explanation') or '')
    line('Coverage: '+data['routing']['overall_coverage'])
    for agent in data.get('detector_results',[]):
        line(f"{agent['agent_name']}: {agent['status']} ({agent['coverage']})",'Heading2')
        scope=(agent.get('evidence') or {}).get('scan_scope')
        if scope:
            line('Scan scope: '+str(scope))
            line((agent.get('evidence') or {}).get('scope_notice') or '')
        for finding in agent.get('findings',[]):
            line(f"{finding['severity']} - {finding.get('location') or 'unknown location'}: {finding.get('reason') or finding['category']}")
            if finding.get('remediation'): line('Remediation: '+finding['remediation'])
    scoring=data.get('scoring',{})
    line('Scoring method: '+scoring.get('method','weighted'))
    if scoring.get('model_version'):line('Model: '+scoring['model_version'])
    if scoring.get('training_scope'):line('Training scope: '+scoring['training_scope'])
    if scoring.get('shap'):
        line('TreeSHAP contributions (model score before policy gates)', 'Heading2')
        line('Baseline: '+str(scoring['shap']['base_value']))
        for agent,value in scoring['shap']['agent_contributions'].items():
            suffix=' (not selected; missingness contribution)' if not scoring['shap'].get('agent_selected',{}).get(agent,True) else ''
            line(f'{agent}{suffix}: {value:+.3f} trust points')
    line('Safety overrides and uncertainty floors remain authoritative. Synthetic-trained models require independent validation. Provisional reports can change.')
    def footer(canvas,document):
        canvas.saveState();canvas.setFont(regular,8);canvas.setFillColorRGB(.35,.35,.35)
        canvas.drawString(document.leftMargin,28,'Guardian audit | '+data['scan_status'])
        canvas.drawRightString(A4[0]-document.rightMargin,28,f'Page {document.page}')
        canvas.restoreState()
    SimpleDocTemplate(stream,pagesize=A4,title='Guardian security audit',author='AI Supply Chain Guardian').build(story,onFirstPage=footer,onLaterPages=footer)
    return Response(stream.getvalue(),media_type='application/pdf',headers={'Content-Disposition':'attachment; filename="guardian-audit.pdf"'})
