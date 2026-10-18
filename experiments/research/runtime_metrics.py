"""Linux operation measurements; sampled tree RSS is explicitly a lower bound.

Kernel ru_maxrss is also retained, separately for this interpreter and its
completed children. Those counters are lifetime high-water marks, not isolated
phase peaks. Sampling includes native subprocesses; it can miss short spikes.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import platform
import resource
from threading import Event, Thread
import time


def rss_tree(pid):
    own, total = 0, 0
    pending, visited = [pid], set()
    while pending:
        current = pending.pop()
        if current in visited: continue
        visited.add(current)
        try:
            rss = int(Path(f"/proc/{current}/statm").read_text().split()[1])*os.sysconf("SC_PAGE_SIZE")
            total += rss
            if current == pid: own = rss
            pending.extend(map(int, Path(f"/proc/{current}/task/{current}/children").read_text().split()))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return own, total


@contextmanager
def measured_phase(name, rows, *, sample_seconds=0.01):
    if platform.system() != "Linux": raise RuntimeError("RSS measurement requires the declared Linux /proc environment")
    event = Event()
    peak = [0, 0]
    def observe():
        while True:
            own, tree = rss_tree(os.getpid())
            peak[0], peak[1] = max(peak[0], own), max(peak[1], tree)
            if event.wait(sample_seconds): break
    observer = Thread(target=observe, daemon=True)
    start = time.perf_counter()
    observer.start()
    row = dict(name=name, status="failed")
    try:
        yield row
        row["status"] = "passed"
    finally:
        row["seconds"] = time.perf_counter()-start
        event.set(); observer.join()
        row.update(sampled_self_peak_rss_bytes=peak[0], sampled_process_tree_peak_rss_bytes=peak[1],
            sampling_interval_seconds=sample_seconds,
            self_kernel_lifetime_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
            completed_children_kernel_lifetime_max_rss_bytes=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss*1024)
        rows.append(row)


def environment():
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), "unknown")
    return dict(python=platform.python_version(), platform=platform.platform(), cpu=cpu,
        OMP_NUM_THREADS=os.getenv("OMP_NUM_THREADS"), OPENBLAS_NUM_THREADS=os.getenv("OPENBLAS_NUM_THREADS"),
        rss_method="10ms /proc process-tree samples (lower bound); Linux kernel lifetime ru_maxrss per interpreter/completed child",
        cold_definition="fresh Python process; OS page cache and previously built native engines retained")
