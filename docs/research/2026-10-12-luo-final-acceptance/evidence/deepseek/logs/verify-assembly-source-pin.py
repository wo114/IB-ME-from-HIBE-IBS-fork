"""Read-only cross-check: live pinned-snapshot smoke vs archived assembly-final.json.

Compares per-file SHA-256 of every imported framework source module and the
profile hash. Prints one JSON verdict. No repository writes.
"""
import json
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
REPO = Path(r"C:\Users\A\.codex\worktrees\luo-acceptance-evidence\IB-ME-from-HIBE-IBS")
ARCHIVED = REPO / "docs/research/2026-10-11-luo-c64b-handoff/evidence/assembly-final.json"
LIVE = WS / "logs/assembly-handoff-pinned-live.json"

archived = json.loads(ARCHIVED.read_text(encoding="utf-8"))
live = json.loads(LIVE.read_text(encoding="utf-8"))

a_src, l_src = archived["source_sha256"], live["source_sha256"]
missing = sorted(set(a_src) - set(l_src))
extra = sorted(set(l_src) - set(a_src))
diff = sorted(k for k in a_src if k in l_src and a_src[k] != l_src[k])

verdict = dict(
    archived_status=archived["status"],
    live_status=live["status"],
    archived_target_head=archived["target_head"],
    live_pinned_head=live["target_head"],
    archived_profile_sha256=archived["profile_sha256"],
    live_profile_sha256=live["profile_sha256"],
    profile_hash_identical=archived["profile_sha256"] == live["profile_sha256"],
    source_files_archived=len(a_src),
    source_files_live=len(l_src),
    source_files_missing_live=missing,
    source_files_extra_live=extra,
    source_files_hash_mismatch=diff,
    all_33_source_hashes_identical=not (missing or extra or diff),
    archived_checks=len(archived["checks"]),
    live_checks=len(live["checks"]),
    check_names_identical=archived["checks"] == live["checks"],
    signature_bytes_match=archived["signature_bytes"] == live["signature_bytes"] == 16383,
    outer_payload_bytes_match=archived["outer_payload_bytes"] == live["outer_payload_bytes"] == 20415,
    application_bytes_match=archived["application_bytes"] == live["application_bytes"] == 3924,
    live_private_artifacts_saved=live["private_artifacts_saved"],
)
print(json.dumps(verdict, ensure_ascii=False, indent=2))
raise SystemExit(0 if verdict["all_33_source_hashes_identical"]
                 and verdict["profile_hash_identical"]
                 and verdict["check_names_identical"] else 2)
