"""Render the maintained developer guide to an A4 PDF (ReportLab required)."""
from pathlib import Path
import re
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Preformatted, Spacer, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import reportlab

ROOT=Path(__file__).resolve().parents[1]


def main():
    fonts=Path(reportlab.__file__).parent/'fonts'
    pdfmetrics.registerFont(TTFont('GuideSans',str(fonts/'Vera.ttf')))
    pdfmetrics.registerFont(TTFont('GuideBold',str(fonts/'VeraBd.ttf')))
    mono=Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')
    pdfmetrics.registerFont(TTFont('GuideMono',str(mono if mono.exists() else fonts/'Vera.ttf')))
    styles=getSampleStyleSheet()
    for key,size,leading in [('BodyText',10,14),('Title',25,30),('Heading1',20,25),('Heading2',14,18),('Heading3',11,15)]:
        styles[key].fontName='GuideBold' if key!='BodyText' else 'GuideSans'
        styles[key].fontSize=size;styles[key].leading=leading
        styles[key].textColor=colors.HexColor('#112e48')
    code=ParagraphStyle('GuideCode',fontName='GuideMono',fontSize=9,leading=12,
        backColor=colors.HexColor('#eef3f8'),borderPadding=8,spaceBefore=6,spaceAfter=10)
    target=ROOT/'output/pdf/Guardian_Developer_Setup_Guide.pdf'
    target.parent.mkdir(parents=True,exist_ok=True)
    story=[];lines=(ROOT/'docs/DEVELOPER_GUIDE.md').read_text().splitlines();i=0
    while i<len(lines):
        line=lines[i];i+=1
        if not line.strip():continue
        if line=='---':story.append(PageBreak());continue
        if line.startswith('```'):
            chunk=[]
            while i<len(lines) and not lines[i].startswith('```'):
                if len(lines[i])>99:raise ValueError('Code line too wide: '+lines[i])
                chunk.append(lines[i]);i+=1
            i+=1
            story.append(Preformatted('\n'.join(chunk),code));continue
        heading=re.match(r'^(#{1,3}) (.*)',line)
        if heading:
            story.append(Paragraph(escape(heading[2]),styles['Heading'+str(len(heading[1]))]));continue
        if line.startswith('- '):
            story.append(Paragraph(escape(line[2:]),styles['BodyText'],bulletText='\u2022'));continue
        para=[line]
        while i<len(lines) and lines[i].strip() and not lines[i].startswith(('#','```','- ')) and lines[i]!='---':
            para.append(lines[i]);i+=1
        story.append(Paragraph(escape(' '.join(para)),styles['BodyText']));story.append(Spacer(1,5))
    def chrome(canvas,doc):
        canvas.saveState();w,h=A4
        canvas.setFillColor(colors.HexColor('#007fa3'));canvas.rect(0,h-9,w,9,fill=1,stroke=0)
        canvas.setFont('GuideSans',8);canvas.setFillColor(colors.HexColor('#526779'))
        canvas.drawString(42,23,'GUARDIAN | Developer setup | 19 October 2026')
        canvas.drawRightString(w-42,23,f'{doc.page}')
        canvas.restoreState()
    SimpleDocTemplate(str(target),pagesize=A4,leftMargin=44,rightMargin=44,topMargin=34,bottomMargin=42,
        title='AI Supply Chain Guardian - Developer Setup Guide',author='AI Supply Chain Guardian').build(story,onFirstPage=chrome,onLaterPages=chrome)
    print(target)


if __name__=='__main__':main()
