"""Read-only checks for the dated draft and its public source evidence.

Does not generate keys, load secret states or execute cryptographic backends.
Optionally pass --record to write a small validation receipt beside the draft.
"""
from pathlib import Path
from hashlib import sha256
from statistics import median
from zipfile import ZipFile
from xml.etree import ElementTree as ET
import argparse
import json
import re

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
W={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
COUNT=0


def check(condition, message):
    global COUNT
    if not condition:raise AssertionError(message)
    COUNT+=1


def digest(path):return sha256(path.read_bytes()).hexdigest()


def check_fooli_source(source,facts):
    fooli=json.loads((ROOT/'docs/research/2026-10-19-parameters/fooli-improvement-search.json').read_text('utf-8'))
    check(len(facts['fooli']['selected'])==3,'FooLi three selected points')
    for saved,n in zip(facts['fooli']['selected'],(1024,2048,4096)):
        rows=[r for r in fooli['target_search']['all_cases'] if r['n']==n and r['q']==2**127-1 and r['g']==16]
        expected=min(rows,key=lambda row:row['m_bar'])
        check(saved==expected,'FooLi selected source row')
        check(saved['d']==saved['m_bar']+2*saved['w'],'FooLi full dimension')
        values=(f"{saved['core_svp_classical_bits']:.1f}／{saved['core_svp_quantum_bits']:.1f}")
        check(f"| {n} | {saved['d']:,} | {values} |" in source,'FooLi report row')
    check('门内穷举否定' not in source and '同等口径下的对象规模' not in source,'bounded FooLi wording')
    check('搜索下限不表示已求出实际最便宜攻击' in source,'low-block search floor')
    check(facts['fooli']['in_gate_search']==fooli['in_gate_search']['stats'],'FooLi finite grid source')


def main(record=False):
    source=(HERE/'研究报告初稿.md').read_text('utf-8')
    facts=json.loads((HERE/'report-facts.json').read_text('utf-8'))
    for path,expected in facts['source_sha256'].items():
        check(digest(ROOT/path)==expected,f'source changed: {path}')
    comparison=json.loads((ROOT/'docs/research/2026-10-18-full-system-luo/evidence/comparison.json').read_text('utf-8'))
    for f,p in zip(facts['profiles'],comparison['profiles']):
        check(f['suite']==p['suite'],'Suite mismatch')
        check(f['security_group']==p['security_group'],'security group')
        check(p['cold_states']==3 and p['restored_decryptions']==9,'repetitions')
        for key,stats in f['timing_seconds'].items():
            raw=p['timing_seconds'][key]
            check(median(raw['observations'])==stats['median'],f'{key}: raw median')
            check(len(raw['observations'])==stats['count'],f'{key}: sample count')
            check(f"{stats['median']:.6f}" in source,f'{key}: missing report value')
        for key,stats in f['bytes'].items():
            if isinstance(stats,dict):
                check(f"{stats['minimum']}–{stats['maximum']}" in source,f'{key}: report size')
    placement=json.loads((ROOT/'docs/research/2026-10-19-full-system-placement/evidence/placement.json').read_text('utf-8'))
    for variant,ops in facts['placement']['timing_seconds'].items():
        for op,stats in ops.items():
            raw=placement['timing_seconds'][variant][op]['observations']
            check(len(raw)==stats['count']==30,'placement count')
            check(median(raw)==stats['median'],'placement raw median')
            check(f"{stats['median']*1000:.3f}" in source,'placement table')
    check(facts['new_cryptographic_runs']==facts['private_state_files_opened']==0,'scope')
    check(facts['final_three_selected'] is False,'representatives not final')
    for path,expected in [
        ('docs/IBME_作品报告.md','d3ae98a1cd4699b2be3cd8474f8607ae5415f0bfb60d83530b3f8f8679040957'),
        ('ib-me.pptx','c1bd68722c4f2fee16f86a3ad8343a36b6223c0d07b3d9a27238b555c8dea4b4')]:
        check(digest(ROOT/path)==expected,'old artifact changed: '+path)
    links=re.findall(r'!?\[[^\]]*\]\(([^)]+)\)',source)
    for target in links:
        path=(HERE/target).resolve()
        check(path.is_relative_to(ROOT) and path.exists(),'bad local link: '+target)
    check(len(re.findall(r'^## 第\d章',source,re.M))==7,'seven developed chapters')
    check(len(re.findall(r'^\[\d+\]',source,re.M))==14,'bibliography')
    check('<!-- generated:timing:start -->\n\n|' in source,'filled table')
    check('最终三代表尚未锁定' in source,'selection boundary')
    check('工作假设' in source and '不能解释为格密码算法本身' in source,'claim boundaries')
    check_fooli_source(source,facts)
    with ZipFile(HERE/'研究报告初稿.docx') as z:
        xml=ET.fromstring(z.read('word/document.xml'))
        styles=ET.fromstring(z.read('word/styles.xml'))
        check(not styles.findall('.//w:pBdr',W),'title border residue')
        tables=xml.findall('.//w:tbl',W)
        check(len(tables)==11,'docx tables')
        docx_rows=[]
        for tbl in tables:
            rows=[]
            for row in tbl.findall('w:tr',W):
                rows.append([''.join(node.text or '' for node in cell.findall('.//w:t',W))
                             for cell in row.findall('w:tc',W)])
            docx_rows.append(rows)
        md_tables=[];current=[]
        for line in source.splitlines()+['']:
            if line.startswith('|'):
                cells=[x.strip() for x in line.strip('|').split('|')]
                if not all(re.fullmatch('[: -]+',x) for x in cells):
                    current.append([re.sub(r'\[([^\]]+)\]\([^)]+\)',r'\1',x) for x in cells])
            elif current:md_tables.append(current);current=[]
        for n,(left,right) in enumerate(zip(md_tables,docx_rows),1):
            check(left==right,f'DOCX and Markdown table {n}')
        check(len(md_tables)==len(docx_rows),'all tables compared')
        check(len([n for n in z.namelist() if n.startswith('word/media/')])==6,'six report figures')
        fulltext=''.join(e.text or '' for e in xml.findall('.//w:t',W))
        for word in ('BOTTOM','HKDF-SHA256','AES-256-GCM','Pan–Wagner','最终三代表'):
            check(word in fulltext,'DOCX content: '+word)
    result={'status':'passed','checks':COUNT,'new_cryptographic_runs':0,
            'files':{p.name:digest(p) for p in [HERE/'研究报告初稿.md',HERE/'研究报告初稿.docx',HERE/'report-facts.json']},
            'layout_review':'separate mandatory page-image review; this script does not certify layout',
            'private_state_files_opened':0,'old_report_and_ppt_sha256_unchanged':True}
    if record:(HERE/'validation.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--record',action='store_true')
    main(p.parse_args().record)
