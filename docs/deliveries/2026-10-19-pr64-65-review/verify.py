"""Offline verification of frozen review sources, JUnit and static plans."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]


def require(condition,message):
    if not condition:
        raise ValueError(message)


def main():
    record=json.loads((HERE/'review.json').read_bytes())
    source=record['pr65_corrected']
    require(source=='8e87066b094796b9380d261da32291e5d3bc92f5','source changed')
    for name,expected in record['source_sha256_lf'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'unsafe source path')
        raw=subprocess.check_output(['git','show',source+':'+name],cwd=ROOT).replace(b'\r\n',b'\n')
        require(sha256(raw).hexdigest()==expected,'source hash changed: '+name)
    unique=set()
    counts=[]
    for run in record['junit']:
        require(Path(run['file']).name==run['file'],'unsafe JUnit path')
        raw=(HERE/run['file']).read_bytes().replace(b'\r\n',b'\n')
        require(sha256(raw).hexdigest()==run['sha256_lf'],'JUnit hash changed')
        xml=ET.fromstring(raw)
        rows=list(xml.iter('testcase'))
        require(all('hostname' not in n.attrib for n in xml.iter()),'hostname not removed')
        require(len(rows)==run['passed'],'JUnit count differs')
        for row in rows:
            require(all(row.find(k) is None for k in ('failure','error','skipped')),'test did not pass')
            unique.add((row.get('classname'),row.get('name')))
        counts.append(len(rows))
    require(counts==[42,13] and len(unique)==record['unique_test_identities']==55,'test selection changed')
    for name,expected in record['artifact_sha256_lf'].items():
        require(Path(name).name==name,'unsafe artifact path')
        require(sha256((HERE/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest()==expected,'artifact changed')
    plan=json.loads((HERE/'pr64-plan.json').read_bytes())
    require(plan['execution']=='not_executed' and plan['mode']=='preflight-only','preflight scope changed')
    require(set(plan['suites'])=={'mldsa44','falcon512','srgg-I','sageloli-I'},'plan families differ')
    require(all(p['preflight']['ok'] for p in plan['suites'].values()),'preflight failed')
    control=json.loads((HERE/'pr64-binding-controls.json').read_bytes())
    require(control['status']=='passed' and control['negative_controls']==3,'binding controls changed')
    require(record['fresh_C2_lifecycle_runs']==record['fresh_FooLi_target_instances']==0,'target-run scope changed')
    require(record['security_claim']=='none' and record['backend_admitted'] is False
            and record['parameters_are_formal'] is False,'security metadata changed')
    print(json.dumps(dict(status='passed',source_mode='frozen Git 8e87066',
                          tests=counts,unique_tests=len(unique),static_plans=4,binding_negative_controls=3)))


if __name__=='__main__':
    main()
