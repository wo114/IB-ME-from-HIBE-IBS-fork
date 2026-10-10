"""Bounded public-source retrieval; never overwrite an existing paper cache.

Only identified primary public URLs are used. Errors and HTML are recorded,
not installed as a PDF. No login, subscription or access restriction bypass.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from urllib.request import Request, urlopen


SOURCES = (
    ("gkr2025", "2025_adaptive_hibe_goyal.pdf", ("https://eprint.iacr.org/2025/291.pdf",)),
    ("sageloli2023", "2023_shorter_faster_ibs_sageloli.pdf", (
        "https://eprint.iacr.org/2023/489.pdf", "https://inria.hal.science/hal-04107694/document")),
    ("srgg2025", "2025_efficient_ibs_jia.pdf", (
        "https://ietresearch.onlinelibrary.wiley.com/doi/pdf/10.1049/ise2/6684889",
        "https://downloads.hindawi.com/journals/ietis/2025/6684889.pdf")),
    ("yu2026", "2026_ibs_ibme_yu.pdf", ()),
)
MAX_BYTES = 16 * 2**20


def fetch(entry, directory):
    source_id, filename, urls = entry
    target = directory / filename
    if target.exists():
        raw = target.read_bytes()
        if not raw.startswith(b"%PDF") or not 50000 <= len(raw) <= MAX_BYTES:
            raise ValueError("preserved existing cache is not a plausible bounded PDF")
        return dict(source_id=source_id, path=target.as_posix(), status="existing-cache-unmodified",
                    bytes=len(raw), sha256=sha256(raw).hexdigest())
    attempts = []
    for url in urls:
        try:
            request = Request(url, headers={"User-Agent": "IBME research source archive"})
            with urlopen(request, timeout=20) as response:
                raw = response.read(MAX_BYTES + 1)
                resolved, content_type = response.geturl(), response.headers.get("Content-Type", "")
            if not 50000 <= len(raw) <= MAX_BYTES or not raw.startswith(b"%PDF"):
                raise ValueError(f"not a bounded plausible PDF (bytes={len(raw)}, content_type={content_type})")
            from pypdf import PdfReader
            from io import BytesIO
            reader = PdfReader(BytesIO(raw))
            excerpt = (reader.pages[0].extract_text() or "")[:240]
            # Exclusive creation also protects a concurrent teammate cache.
            with target.open("xb") as handle: handle.write(raw)
            return dict(source_id=source_id, path=target.as_posix(), status="downloaded", source_url=url,
                        resolved_url=resolved, bytes=len(raw), pages=len(reader.pages), sha256=sha256(raw).hexdigest(),
                        version="Current public URL at retrieval; no numeric version inferred", title_check_excerpt=excerpt,
                        attempts=attempts)
        except Exception as exc:
            attempts.append(dict(url=url, error=f"{type(exc).__name__}: {exc}"))
    return dict(source_id=source_id, status="not-obtained", intended_path=target.as_posix(), attempts=attempts,
                reason="No open PDF URL located" if not urls else "Public source retrieval failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--papers", type=Path, default=Path("papers"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.papers.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        entries = list(pool.map(lambda entry: fetch(entry, args.papers), SOURCES))
    result = dict(schema_version=1, retrieval_date=datetime.now(timezone(timedelta(hours=8))).date().isoformat(),
                  entries=entries, tex_sources_obtained=False, scope="Identified public URLs and existing cache only; no subscription access attempted")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({entry["source_id"]: entry["status"] for entry in entries}))


if __name__ == "__main__": main()
