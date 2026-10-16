from app.native_license import ROOT,identify_text,template_index,normalize


def test_pinned_templates_recognized():
    for path in ROOT.glob('*.txt'):
        ids,op,confidence,warnings=identify_text(path.read_text())
        candidates=template_index()[normalize(path.read_text())]
        if len(candidates)==1:
            assert ids==[path.stem] and confidence>.8 and not warnings
        else:
            assert not ids and confidence==0 and warnings


def test_changed_obligations_and_header_only_unknown():
    text=(ROOT/'MIT.txt').read_text()
    assert not identify_text(text+'\nAdditional restriction: commercial use prohibited.')[0]
    assert not identify_text('MIT License')[0]


def test_copyright_notice_can_vary():
    text=(ROOT/'MIT.txt').read_text().replace('<year> <copyright holders>','2026 Example Author')
    assert identify_text(text)[0]==['MIT']


def test_copyright_prefixed_restrictions_are_not_discarded():
    text=(ROOT/'MIT.txt').read_text()
    for clause in ('Copyright commercial use prohibited.',
                   'Copyright 2026 Example Author. Commercial use prohibited.',
                   'Copyright 2026 Example Author; redistribution requires permission.',
                   'Copyright 2026 Example Author - redistribution forbidden.',
                   'Copyright 2026 Example Author provided you pay.'):
        assert not identify_text(text+'\n'+clause)[0]
