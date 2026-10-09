"""Reproduce Appendix E's counting units, not its security estimator or sampler.

The archived HAL v1 PDF (pp.71--72) counts logarithmic bits, then labels
division by 1e6 as 'Mo'. Keep that output separate from byte normalization and
an exact fixed-coefficient-width public-key count. These are counting models,
not implemented wire lengths or newly validated security parameters.
"""

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import sys

PAPER = "papers/2023_shorter_faster_ibs_sageloli.pdf"
PAPER_SHA = "0e92f184828bc8643a774e9c334b14689346387981e766c311c596239ef73e3e"
ROWS = (("ParamI", 65, 2048, 132, 200), ("ParamII", 153, 2048, 308, 200))


def _integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper: raise ValueError("bounded integer required")


def parameter_row(name, k, degree, columns, tail_bits):
    for value, low, high in ((k, 4, 512), (degree, 4, 4096), (columns, 1, 4096), (tail_bits, 1, 512)):
        _integer(value, low, high)
    if degree & (degree - 1) or not max(2 * k, 21) < columns <= 2 * k + k / 2:
        raise ValueError("Table 4 ring degree/columns condition fails")
    # Float transcription matches Appendix E's natural logarithms and constants.
    # It is deliberately not a certified finite sampling or norm certificate.
    eps, q = 2.0**(-tail_bits), 3**k
    def f(m, n, constant): return math.sqrt(m) + 2 * math.pi * constant * (math.sqrt(n) + math.sqrt(m * math.log(3)))
    def r(m): return math.sqrt(math.log(2 * m * (1 + 1 / eps)) / math.pi)
    binom = math.sqrt(0.5) * f(degree * k, columns - k, 1 / (4 * math.pi))
    sid = max(math.sqrt(11) * r(degree * k) * 4 * math.sqrt(degree * binom**2 + 1), 12 * r(degree * columns))
    gauss = sid / math.sqrt(2 * math.pi) * f(degree * k, columns, 1 / (2 * math.pi))
    ssign = max(math.sqrt(11) * r(degree * k) * math.sqrt(degree * gauss**2 + 1), 12 * r(degree * (columns + k)))
    b1, b2 = math.sqrt(2 * degree * columns) * ssign, math.sqrt(2 * degree * k) * ssign
    bit_counts = dict(signature=math.ceil(columns * degree * math.log2(2 * b1) + k * degree * math.log2(2 * b2)),
                      public=math.ceil(columns * degree * math.log2(q)),
                      master=math.ceil((columns - k) * k * degree * math.log2(3)),
                      identity_key=math.ceil((columns + k) * k * degree * math.log2(math.sqrt(2 * degree) * sid)))
    widths = dict(public=(q - 1).bit_length(), response_block1=math.ceil(math.log2(2 * math.floor(b1) + 1)),
                  response_block2=math.ceil(math.log2(2 * math.floor(b2) + 1)))
    fixed_signature_bits = degree * (columns * widths["response_block1"] + k * widths["response_block2"])
    return dict(name=name, k=k, degree=degree, columns=columns, tail_bits=tail_bits, q_decimal=str(q),
                log2_sid=math.log2(sid), log2_ssign=math.log2(ssign),
                appendix_E_approximate_information_bits=bit_counts,
                appendix_printed_Mo_numeric={key: round(value / 10**6, 2) for key, value in bit_counts.items()},
                normalized_information_bytes={key: (value + 7) // 8 for key, value in bit_counts.items()},
                coefficient_width_bits=widths,
                fixed_width_public_bytes=(columns * degree * widths["public"] + 7) // 8,
                fixed_width_signature_bytes_excluding_nonces_frame=(fixed_signature_bits + 7) // 8,
                fits_legacy_uint32=q < 2**32, fits_module_ref_uint64=q < 2**64,
                modulus_is_prime=False, implemented_encoding=False, gaussian_sampler_implemented=False,
                security_estimator_executed=False, security_claim="none", backend_admitted=False,
                notes="q=3^k is composite here. Floating Appendix E counts are estimates; fixed-width counts exclude framing, nonces and context. All model/parameter mapping remains pending.")


def audit():
    root = Path(__file__).resolve().parents[2]
    if sha256((root / PAPER).read_bytes()).hexdigest() != PAPER_SHA: raise RuntimeError("archived source version changed")
    return dict(source_pdf=PAPER, source_sha256=PAPER_SHA, source_version="HAL hal-04107694v1, submitted 2023-05-26",
                source_locations="PDF p.28 Table 6/7; pp.69--73 Appendix E; printed pages are PDF minus one",
                rows=[parameter_row(*row) for row in ROWS], units_issue_observed=True,
                units_issue_scope="Appendix E formulas count bits but print bits/1e6 with Mo labels. No byte encoding or attack is inferred.",
                security_claim="none", backend_admitted=False, performance_measured=False,
                python=sys.version, platform=platform.platform(), processor=platform.processor(), repeats=1,
                identity_message_lengths="Not applicable: counting only; signature nonce/framing excluded",
                rom="Paper ROM/QROM declarations only; no scheme or proof implemented")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(dict(rows=len(result["rows"]), units_issue_observed=True, security_claim="none")))


if __name__ == "__main__": main()
