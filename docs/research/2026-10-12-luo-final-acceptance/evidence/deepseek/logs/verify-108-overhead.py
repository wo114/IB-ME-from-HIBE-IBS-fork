"""Arithmetic-only verification of the frozen 108-byte payload overhead.

No Setup/Extract/Sign, no private material: uses the public protocol framing
constants and a synthetic signature byte string of the recorded length.
"""
import json
import sys
from pathlib import Path

REPO = Path(r"C:\Users\A\.codex\worktrees\luo-acceptance-evidence\IB-ME-from-HIBE-IBS")
sys.path[:0] = [str(REPO), str(REPO / "src")]

from ibme.core.encoding import encode_bytes
from ibme.protocol.baseline import DOMAIN_SIGNATURE
from ibme.protocol.byteauth import ENVELOPE_OVERHEAD, MAGIC_ENVELOPE, COMMITMENT_BYTES, encode_bound_message

sig_len = 16383
app = 3924
synthetic_sig = bytes(sig_len)
payload = DOMAIN_SIGNATURE + encode_bytes(synthetic_sig) + encode_bytes(encode_bound_message(bytes(COMMITMENT_BYTES), b"M" * app))

parts = dict(
    domain_signature=len(DOMAIN_SIGNATURE),
    sig_length_prefix=len(encode_bytes(synthetic_sig)) - sig_len,
    msg_length_prefix=4,
    envelope_overhead=ENVELOPE_OVERHEAD,
)
total = sum(parts.values())
verdict = dict(
    parts=parts,
    sum_overhead=total,
    claimed_108=108,
    overhead_is_108=total == 108,
    envelope_breakdown=dict(magic=len(MAGIC_ENVELOPE), inner_length_field=8, commitment=COMMITMENT_BYTES,
                            sum=len(MAGIC_ENVELOPE) + 8 + COMMITMENT_BYTES, equals_envelope_overhead=ENVELOPE_OVERHEAD == len(MAGIC_ENVELOPE) + 8 + COMMITMENT_BYTES),
    synthetic_payload_len=len(payload),
    formula_len=sig_len + total + app,
    formula_matches=len(payload) == sig_len + total + app,
    compact_outer_at_max_application=16383 + total + 3924,
    compact_outer_is_20415=16383 + total + 3924 == 20415,
)
print(json.dumps(verdict, ensure_ascii=False, indent=2))
raise SystemExit(0 if verdict["overhead_is_108"] and verdict["formula_matches"] and verdict["compact_outer_is_20415"] else 2)
