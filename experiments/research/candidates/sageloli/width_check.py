"""192-bit interval checks of Table 2/4 widths, without a security claim."""
import argparse
import json
from pathlib import Path

from sage.all import QQ, RealIntervalField
from ibme.lattice.chkp.gaussian import interval_bounds


def check_widths():
    field = RealIntervalField(192)
    epsilon = QQ(1)/2**64
    # Paper p.12 Corollary 1, using conservative C=38 from C<38.
    def f(m, n):
        return field(m).sqrt()+2*field.pi()*38*(field(n).sqrt()+(field(m)*field(3).log()).sqrt())
    def r(x):
        return (field(2*x*(1+1/epsilon)).log()/field.pi()).sqrt()
    out = []
    profiles = (("matrix", 2, 4, 16, 1, 2**14, 2**28),
                ("ring", 1, 9, 22, 4, 2**18, 2**33))
    for kind, n, k, m, d, sid, ssign in profiles:
        if kind == "matrix":
            w = n*k
            binomial_norm = field(QQ(1)/2).sqrt()*f(w, m-w)
            id1 = field(11).sqrt()*r(w)*(binomial_norm**2+1).sqrt()
            id2 = 12*r(m)
            gaussian_norm = field(sid)/(2*field.pi()).sqrt()*f(w, m)
            sg1 = field(11).sqrt()*r(w)*(gaussian_norm**2+1).sqrt()
            sg2 = 12*r(m+w)
        else:
            w = d*k
            binomial_norm = field(QQ(1)/2).sqrt()*f(w, m-k)
            id1 = field(11).sqrt()*r(w)*(16*d*binomial_norm**2+1).sqrt()
            id2 = 12*r(d*m)
            gaussian_norm = field(sid)/(2*field.pi()).sqrt()*f(w, m)
            sg1 = field(11).sqrt()*r(w)*(d*gaussian_norm**2+1).sqrt()
            sg2 = 12*r(d*(m+k))
        smoothing = r(w)**2
        passed = (sid >= max(interval_bounds(id1)[1], interval_bounds(id2)[1])
                  and ssign >= max(interval_bounds(sg1)[1], interval_bounds(sg2)[1])
                  and 16 >= interval_bounds(smoothing)[1])
        if not passed:
            raise ValueError("Table width interval check failed: "+kind)
        out.append({"kind": kind, "C_upper": 38, "epsilon_bits": 64,
            "r_squared": 16, "sid": sid, "ssign": ssign,
            "table_width_inequalities_pass": passed,
            "sid_requirement": str(id1), "sid_smoothing_requirement": str(id2),
            "ssign_requirement": str(sg1), "ssign_smoothing_requirement": str(sg2),
            "smoothing_r_squared_requirement": str(smoothing),
            "scope": "Width formulas only; security, regularity and numerical Gaussian TV unproved",
            "security_claim": "none", "backend_admitted": False})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = check_widths()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
