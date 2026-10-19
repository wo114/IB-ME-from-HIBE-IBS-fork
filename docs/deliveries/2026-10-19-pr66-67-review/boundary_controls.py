"""Safe boundary controls: the native function is replaced, never called."""
from pathlib import Path
import json
from types import SimpleNamespace
import numpy as np
import experiments.research.wang_pw_numeric.gpv_kernel as kernel

B=np.eye(2,dtype=np.int64)
star=np.eye(2,dtype=np.float64)
norms=np.ones(2,dtype=np.float64)
P=np.zeros((2,1),dtype=np.int64)
cases={
    'wrong_basis_dtype':dict(B=B.astype(np.float32)),
    'short_norm_array':dict(norms=np.ones(1,dtype=np.float64)),
    'noncontiguous_norm_array':dict(norms=np.array([1.,0.,1.,0.])[::2]),
    'nan_sigma':dict(sigma=float('nan')),
    'zero_threads':dict(threads=0),
}
rows=[]
for name,change in cases.items():
    seen=[]
    kernel._LIB=SimpleNamespace(sample_x=lambda *args:seen.append(True))
    args=dict(B=B,star=star,norms=norms,P=P,sigma=2.,threads=1)
    args.update(change)
    try:
        kernel.sample_x_c(**args)
    except (TypeError,ValueError,AssertionError) as exc:
        rejected=True
    else:
        rejected=False
    rows.append(dict(case=name,rejected_before_native=rejected,native_entry_reached=bool(seen)))
result=dict(source_commit='cbbfd442cd3992369570f4d32004a9db0bc5cfd7',native_function_replaced=True,unsafe_native_execution=False,cases=rows)
Path('../native-controls.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
