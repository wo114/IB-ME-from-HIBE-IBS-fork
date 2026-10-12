"""Run one bounded CHKP research lifetime, saving private checkpoints locally.

Run in WSL Sage. The output MUST be inside the ignored test-results directory.
Each phase runs once: a pending marker blocks retries after failure or crash.
Receipts publish only counts, durations and checks, never sampled secrets.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import subprocess
import time

from ibme.cli_state import StateBusyError, key_issuance_lock

BASE = Path(__file__).resolve().parents[2]
PHASES = ('setup', 'parent', 'leaf', 'roundtrip')


def sync_directory(directory):
    if os.name == 'posix':
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write(path, data):
    temp = path.with_name(path.name + '.tmp')
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)
    sync_directory(path.parent)


def private_directory(value):
    directory = Path(value).resolve()
    if (not directory.is_relative_to(BASE / 'test-results')
            or directory == BASE / 'test-results'):
        raise ValueError('private lifetime must have its own directory under ignored test-results')
    result = subprocess.run(['git', 'check-ignore', '--quiet', '--',
                             str((directory / 'private.bin').relative_to(BASE))],
                            cwd=BASE, capture_output=True, check=False)
    if result.returncode != 0:
        raise ValueError('private lifetime path is not ignored by Git')
    return directory


def require_lifetime_ready(directory, through):
    """Check the complete prefix, including old receipts from this driver."""
    if any(directory.glob('*.pending')):
        raise ValueError('lifetime has a pending attempt; no automatic continuation')
    for phase in PHASES[:PHASES.index(through) + 1]:
        try:
            receipt = json.loads((directory / (phase + '.json')).read_bytes())
        except (OSError, ValueError):
            raise ValueError('required lifetime phase is not ready: ' + phase) from None
        if (not isinstance(receipt, dict) or receipt.get('phase') != phase
                or receipt.get('passed') is not True):
            raise ValueError('required lifetime phase is not ready: ' + phase)


class CountedSystem:
    def __init__(self):
        from ibme.core.randomness import SecureRandom
        self.source, self.bytes_used = SecureRandom(), 0

    def read(self, size):
        value = self.source.read(size)
        self.bytes_used += len(value)
        return value


class NoEntropy:
    def read(self, size):
        raise AssertionError('restoration/cache reuse attempted new sampling')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--diagnostics', action='store_true', help='print stack locations every 120 seconds (no local values)')
    args = parser.parse_args(argv)
    try:
        directory = private_directory(args.directory)
    except ValueError as exc:
        parser.error(str(exc))
    if args.phase == 'setup':
        if directory.exists():
            parser.error('setup requires a fresh lifetime directory')
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    if not directory.is_dir():
        parser.error('run setup first')
    try:
        with key_issuance_lock(directory, timeout=0):
            return run_phase(args, parser, directory)
    except StateBusyError:
        parser.error('another writer owns this lifetime directory')


def run_phase(args, parser, directory):
    # A failure affects shared root/parent checkpoints, not only its own phase.
    if any(directory.glob('*.pending')):
        parser.error('lifetime has a pending attempt; no automatic continuation')
    prerequisite = {'parent': 'setup', 'leaf': 'parent', 'roundtrip': 'leaf'}.get(args.phase)
    if prerequisite:
        try:
            require_lifetime_ready(directory, prerequisite)
        except ValueError as exc:
            parser.error(str(exc))
    marker = directory / (args.phase + '.pending')
    receipt_path = directory / (args.phase + '.json')
    if marker.exists() or receipt_path.exists():
        parser.error('this phase already started; no retry of a failed/published lifetime')
    with marker.open('xb') as stream:
        stream.write(b'No automatic retry. Preserve this marker after any failure.\n')
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(directory)
    from ibme.hibe.chkp import (CHKPHIBE, research_params, CHKPPublicKey,
        CHKPMasterSecret, CHKPLevel1SecretKey, CHKPLevel2SecretKey)
    from ibme.protocol.hybrid_hibe import encoded_identity, HybridLimits
    backend, source = CHKPHIBE(), CountedSystem()
    limits = HybridLimits(backend_id=b'chkp')
    receiver, sender = (encoded_identity(b'Bob', limits, b'P'),
                        encoded_identity(b'Alice', limits, b'C'))
    started = time.monotonic()
    receipt = dict(phase=args.phase, security_claim='none', backend_admitted=False,
                   parameters_are_formal=False, randomness='system CSPRNG',
                   identities_are_public_test_labels=True, python=platform.python_version(),
                   platform=platform.platform())
    if args.diagnostics:
        import faulthandler
        faulthandler.dump_traceback_later(120, repeat=True)
    print(json.dumps(dict(event='started', phase=args.phase)), flush=True)
    try:
        if args.phase == 'setup':
            public, master = backend.setup(research_params(), rng=source)
            write(directory/'public.bin', public.to_bytes())
            write(directory/'master.bin', master.to_bytes())
            receipt.update(root_dimension=public.params.m,
                           public_bytes=len(public.to_bytes()), master_bytes=len(master.to_bytes()))
        elif args.phase == 'parent':
            public = CHKPPublicKey.from_bytes((directory/'public.bin').read_bytes())
            master = CHKPMasterSecret.from_bytes((directory/'master.bin').read_bytes())
            if not backend.validate_key_binding(public, master):
                raise AssertionError('source master/public mismatch')
            try:
                parent = backend.extract(master, receiver, rng=source)
            finally:
                write(directory/'master.bin', master.to_bytes())
            write(directory/'parent.bin', parent.to_bytes())
            receipt.update(parent_dimension=2*parent.params.m, parent_bytes=len(parent.to_bytes()))
        elif args.phase == 'leaf':
            public = CHKPPublicKey.from_bytes((directory/'public.bin').read_bytes())
            master = CHKPMasterSecret.from_bytes((directory/'master.bin').read_bytes())
            parent = CHKPLevel1SecretKey.from_bytes((directory/'parent.bin').read_bytes())
            if (not backend.validate_key_binding(public, master)
                    or not backend.validate_key_binding(public, parent)
                    or parent.identity != receiver):
                raise AssertionError('source parent/master/public mismatch')
            # Before the first leaf, both snapshots must hold the same parent.
            # After leaf sampling parent.bin becomes the authoritative cache.
            if backend.extract(master, receiver, rng=NoEntropy()).to_bytes() != parent.to_bytes():
                raise AssertionError('source parent differs from root cached parent')
            try:
                child = backend.derive(parent, sender, rng=source)
            finally:
                write(directory/'parent.bin', parent.to_bytes())
            write(directory/'child.bin', child.to_bytes())
            receipt.update(leaf_dimension=child.params.leaf_dimension, targets=256,
                           child_bytes=len(child.to_bytes()), parent_bytes=len(parent.to_bytes()))
        else:
            public = CHKPPublicKey.from_bytes((directory/'public.bin').read_bytes())
            master = CHKPMasterSecret.from_bytes((directory/'master.bin').read_bytes())
            parent = CHKPLevel1SecretKey.from_bytes((directory/'parent.bin').read_bytes())
            child = CHKPLevel2SecretKey.from_bytes((directory/'child.bin').read_bytes())
            if not all(backend.validate_key_binding(public, key) for key in (master, parent, child)):
                raise AssertionError('restored public/key binding mismatch')
            restored_parent = backend.extract(master, receiver, rng=NoEntropy())
            if (restored_parent.identity != receiver or
                    not backend.validate_key_binding(public, restored_parent) or
                    backend.extract(master, receiver, rng=NoEntropy()).to_bytes() != restored_parent.to_bytes()):
                raise AssertionError('restored parent binding/cache mismatch')
            if backend.derive(parent, sender, rng=NoEntropy()).to_bytes() != child.to_bytes():
                raise AssertionError('restored fixed leaf mismatch')
            seed = source.read(32)
            capsule = backend.encrypt(public, receiver, sender, seed, rng=source)
            if backend.decrypt(child, capsule) != seed:
                raise AssertionError('actual raw encapsulation/decapsulation failed')
            from experiments.attacks.chkp_small_dimension import recover_seed_hashes
            from ibme.hibe.chkp.backend import _noise
            attack = recover_seed_hashes(public.oracle, receiver, sender,
                                         capsule.capsule, _noise(public.params).radius)
            seed_digest = hashlib.sha256(seed).hexdigest()
            if seed_digest not in attack['recovered_seed_sha256']:
                raise AssertionError('public attack did not recover the actual seed hash')
            receipt.update(raw_roundtrip=True, zero_entropy_restore=True,
                           ciphertext_bytes=len(capsule.to_bytes()), public_attack=attack,
                           actual_seed_sha256=seed_digest, public_attack_matches_seed=True)
            write(directory/'capsule.bin', capsule.to_bytes())
        receipt['passed'] = True
    except BaseException as exc:
        # Arithmetic exception messages may embed private values. Publish
        # only the failure class and phase; preserve the pending marker.
        receipt.update(passed=False, failure_type=type(exc).__name__)
    finally:
        receipt.update(seconds=time.monotonic()-started, entropy_bytes=source.bytes_used)
        try:
            import resource
            receipt['process_max_rss_KiB'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except ImportError:
            pass
        if args.diagnostics:
            faulthandler.cancel_dump_traceback_later()
        write(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True)+'\n').encode())
        print(json.dumps(receipt, sort_keys=True), flush=True)
    if receipt['passed']:
        marker.unlink()
        sync_directory(directory)
        return 0
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
