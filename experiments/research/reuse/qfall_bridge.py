"""Bounded PUBLIC FIXTURE adapter to the pinned, unmodified qFALL API.

Deterministic A_bar and {-1,0,1} R are generated solely for reproducible tests.
No production setup, HIBE identity oracle, key format or admission is exposed.
The Rust process performs MP12 gadget/full-basis conversion; Sage independently
checks its complete integer kernel, not just containment.
"""

import json
from pathlib import Path
import subprocess

from ibme.core.randomness import DeterministicRandom

QFALL_REV = "b8eb4842fb80c36f7f3494930ea316472cb75793"
MAX_BYTES = 1024 * 1024


def public_fixture(n, q, m_bar, *, seed):
    if (type(n) is not int or not 1 <= n <= 4 or type(q) is not int
            or not 2 <= q <= 2**40 or type(m_bar) is not int or not 1 <= m_bar <= 96
            or type(seed) is not bytes or not 1 <= len(seed) <= 256):
        raise ValueError("need bounded, explicit public test inputs")
    k = (q - 1).bit_length()
    if m_bar + n*k > 192:
        raise ValueError("public root fixture exceeds 192 dimensions")
    rng = DeterministicRandom(b"IBME:QFALL-PUBLIC-FIXTURE:1" + seed)
    size, mask = (k+7)//8, (1 << k)-1
    def uniform():
        for _ in range(128):
            x = int.from_bytes(rng.read(size), "little") & mask
            if x < q:
                return x
        raise RuntimeError("public fixture uniform draw aborted; no retry")
    a_bar = [[uniform() for _ in range(m_bar)] for _ in range(n)]
    r = []
    for _ in range(m_bar):
        row = []
        for _ in range(n*k):
            bits = rng.read(1)[0]
            row.append((bits & 1) - ((bits >> 1) & 1))
        r.append(row)
    return dict(public_test_fixture=True, n=n, q=q, m_bar=m_bar, a_bar=a_bar, r=r)


def run_fixture(fixture, binary):
    raw = json.dumps(fixture, separators=(",", ":")).encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("fixture byte budget exceeded")
    result = subprocess.run([str(Path(binary))], input=raw, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError("qFALL public fixture process failed: " + result.stderr.decode(errors="replace")[:500])
    if len(result.stdout) > MAX_BYTES:
        raise ValueError("qFALL fixture output exceeds byte budget")
    def unique(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate fixture field")
            output[key] = value
        return output
    return json.loads(result.stdout, object_pairs_hook=unique)


def validate_root(fixture, output):
    from experiments.research.chkp_basis import KernelBasis, ModMatrixReference
    keys = {"public_test_fixture", "n", "q", "m_bar", "k", "a", "basis", "security_claim", "backend_admitted"}
    if type(output) is not dict or set(output) != keys:
        raise ValueError("wrong qFALL public fixture schema")
    if (output["public_test_fixture"] is not True or output["backend_admitted"] is not False
            or output["security_claim"] != "none"):
        raise ValueError("a public fixture cannot claim admission")
    n, q, m_bar = fixture["n"], fixture["q"], fixture["m_bar"]
    k, m = (q-1).bit_length(), m_bar + n*(q-1).bit_length()
    for name, value in (("n", n), ("q", q), ("m_bar", m_bar), ("k", k)):
        if type(output[name]) is not int or output[name] != value:
            raise ValueError("fixture parameters changed")
    def rows(group, height, residues=False):
        if type(group) is not list or len(group) != height:
            raise ValueError("bad fixture row count")
        result = []
        for row in group:
            if type(row) is not list or len(row) != m:
                raise ValueError("bad fixture column count")
            vals = []
            for x in row:
                if type(x) is not str or not 1 <= len(x) <= 32:
                    raise ValueError("bounded canonical integer strings required")
                value = int(x)
                if str(value) != x or abs(value).bit_length() > 64 or (residues and not 0 <= value < q):
                    raise ValueError("noncanonical fixture integer/residue")
                vals.append(value)
            result.append(vals)
        return result
    a, b = rows(output["a"], n, True), rows(output["basis"], m)
    # Check the full defining relation; a complete but unrelated lattice is
    # insufficient. R is a declared public fixture, never a real secret here.
    expected = []
    for i in range(n):
        right = []
        for j in range(n*k):
            gadget = 2**(j % k) if j//k == i else 0
            right.append((gadget - sum(fixture["a_bar"][i][t]*fixture["r"][t][j]
                                      for t in range(m_bar))) % q)
        expected.append(fixture["a_bar"][i] + right)
    if a != expected:
        raise ValueError("qFALL public matrix differs from the declared fixture")
    return KernelBasis(ModMatrixReference(a, q), b)
