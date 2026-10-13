"""Explicit research migration after the identified zero-entropy leaf failure.

This is NOT general tombstone recovery. It accepts only a successful frozen
research root and Bob parent whose sole Alice attempt failed before sampling,
with the independently recorded finite-scalar-domain diagnosis. It leaves the
source untouched and copies the successful master/parent into a fresh branch.
No LLL, GenTrap, RandBasis or sample is allowed. A separately executed complete
leaf preflight must be bound to the unchanged parent and current source hashes.
The ordinary first leaf attempt still executes every constructor check itself.

Private source hashes stay in the ignored intent ledger. Public resume.json
contains only receipt/code hashes, checks and timings; never basis geometry.
"""
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import argparse
import json
import math
import os
from pathlib import Path, PurePosixPath
import random
import secrets
import time
from unittest.mock import patch

from ibme.cli_state import LOCK_FILE, StateBusyError, key_issuance_lock
from experiments.research.chkp_lifecycle import private_directory, sync_directory, write

BASE = Path(__file__).resolve().parents[2]
DIAGNOSTIC = 'leaf_preflight_diagnostic_600.json'
PREFLIGHT = 'leaf_full_preflight_receipt.json'
BINDING = 'leaf_full_preflight_binding.json'
INPUTS = ('public.bin', 'master.bin', 'parent.bin', 'setup.json', 'parent.json',
          'leaf.json', 'leaf.pending', DIAGNOSTIC, PREFLIGHT, BINDING)
CODE_INPUTS = ('experiments/research/chkp_resume_pre_entropy.py',
              'src/ibme/hibe/chkp/backend.py', 'src/ibme/hibe/chkp/objects.py',
              'src/ibme/hibe/chkp/params.py', 'src/ibme/lattice/chkp/finite_gpv.py',
              'src/ibme/lattice/chkp/finite_gaussian.py',
              'src/ibme/lattice/chkp/extended_gpv.py',
              'src/ibme/lattice/chkp/delegation_state.py',
              'src/ibme/lattice/chkp/leaf_state.py')
SCHEMA = 'IBME/CHKP-ZERO-ENTROPY-RESUME/1'
PREFLIGHT_GATES = frozenset((
    'cache_parent_sha_binding', 'cache_source_is_commit_2976c1a', '_gs_geometry_ast_unchanged',
    '_bounded_qq_ast_unchanged', '_bounded_rational_ast_unchanged', 'cache_rational_bit_budget_binding',
    'cache_columns_exactly_match_parent', 'gpv_actual_rows_match_cached_parent',
    'gpv_actual_bit_budget_matches_cache', 'extended_gpv_complete_constructor',
    'exact_geometry_cache_used_once', 'adaptive_paths_admitted', 'real_leaf_identity_matrix_binding',
    '256_total_budget', 'full_extended_smoothing_gate', 'source_parent_unchanged',
    'source_files_unchanged_during_preflight'))


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate evidence field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite evidence')))
    if type(value) is not dict:
        raise ValueError('evidence must be an object')
    return value


def _dump(path, value):
    write(path, (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())


def _regular(path):
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()) or not path.is_file():
        raise ValueError('source files must be regular files without links')


def _inventory(directory):
    """Hash data/evidence files, excluding the held OS byte-range lock file."""
    result = {}
    for path in sorted(directory.iterdir()):
        _regular(path)
        if path.name == LOCK_FILE:
            continue  # Windows cannot read the range held by our separate handle.
        digest = sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(2**20), b''):
                digest.update(chunk)
        result[path.name] = digest.hexdigest()
    return result


def _flags(receipt):
    return (receipt.get('security_claim') == 'none' and
            receipt.get('backend_admitted') is False and
            receipt.get('parameters_are_formal') is False)


def _validate_evidence(blobs):
    receipts = {phase: _json(blobs[phase + '.json']) for phase in ('setup', 'parent', 'leaf')}
    for phase, value in receipts.items():
        if value.get('phase') != phase or not _flags(value):
            raise ValueError('source phase or security flags mismatch')
        entropy = value.get('entropy_bytes')
        seconds = value.get('seconds')
        if type(entropy) is not int or entropy < 0 or type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError('source measurement is incomplete')
        if phase != 'leaf' and (value.get('passed') is not True or entropy <= 0):
            raise ValueError('source root and parent must be actual successful results')
    leaf = receipts['leaf']
    if leaf.get('passed') is not False or leaf['entropy_bytes'] != 0 or leaf.get('failure_type') != 'ValueError':
        raise ValueError('only the identified zero-entropy leaf failure is recoverable')
    diagnostic = _json(blobs[DIAGNOSTIC])
    expected = {'diagnostic': 'read_only_original_leaf_preflight',
                'sampler_sample_called': False, 'state_mutation_called': False,
                'private_geometry_printed': False, 'preflight_passed': False,
                'original_failure_gate_identified': True, 'parent_snapshot_unchanged': True,
                'error_type': 'ValueError', 'outcome': 'preflight_exception',
                'safe_error': 'Scalar squared width outside independent finite profile 1..2^80'}
    if any(diagnostic.get(key) != value or (type(value) is bool and diagnostic.get(key) is not value)
           for key, value in expected.items()):
        raise ValueError('source diagnostic does not identify the admitted pre-entropy gate')
    if type(diagnostic.get('entropy_consumed')) is not int or diagnostic['entropy_consumed'] != 0:
        raise ValueError('diagnostic consumed entropy or lacks an exact counter')
    stack = diagnostic.get('stack')
    if not isinstance(stack, list) or not any(
            isinstance(frame, dict) and str(frame.get('file', '')).replace('\\', '/').endswith('/finite_gpv.py')
            and frame.get('function') == '__init__' for frame in stack):
        raise ValueError('diagnostic must locate the actual finite GPV constructor gate')
    return receipts, {key: diagnostic[key] for key in expected} | {'entropy_consumed': 0}


def _validate_preflight(blobs, source):
    receipt, binding = _json(blobs[PREFLIGHT]), _json(blobs[BINDING])
    parent_relative = (source/'parent.bin').relative_to(BASE).as_posix()
    binding_relative = (source/BINDING).relative_to(BASE).as_posix()
    if (receipt.get('schema') != 'ibme.chkp.leaf-preflight.v1'
            or binding.get('schema') != 'ibme.chkp.leaf-preflight-binding.v1'
            or binding.get('source_parent_relative') != parent_relative
            or receipt.get('source_parent_relative') != parent_relative
            or receipt.get('private_binding_relative') != binding_relative
            or binding.get('parent_snapshot_sha256') != sha256(blobs['parent.bin']).hexdigest()
            or binding.get('receipt_sha256') != sha256(blobs[PREFLIGHT]).hexdigest()):
        raise ValueError('preflight receipt is not bound to the current failed parent')
    if any(receipt.get(name) is not value for name, value in (
            ('passed', True), ('sample_called', False), ('state_mutation_called', False),
            ('gso_recomputed', False), ('source_parent_unchanged', True),
            ('cache_geometry_old_new_ast_unchanged', True))):
        raise ValueError('preflight did not complete its admitted zero-entropy route')
    if (type(receipt.get('targets')) is not int or receipt['targets'] != 256
            or type(receipt.get('entropy_bytes')) is not int or receipt['entropy_bytes'] != 0):
        raise ValueError('preflight must cover all 256 targets without entropy')
    gates = receipt.get('all_gates')
    if type(gates) is not dict or set(gates) != PREFLIGHT_GATES or any(value is not True for value in gates.values()):
        raise ValueError('preflight gate list is empty, partial or failed')
    hashes = receipt.get('source_sha256')
    if type(hashes) is not dict or not hashes or receipt.get('source_relative') != sorted(hashes):
        raise ValueError('preflight source list is empty or inconsistent')
    required = {path.relative_to(BASE).as_posix() for path in (BASE/'src'/'ibme').rglob('*.py')}
    required.add((source/'leaf_full_preflight.py').relative_to(BASE).as_posix())
    if not required.issubset(hashes):
        raise ValueError('preflight source map omits a current implementation file')
    for name, digest in hashes.items():
        path = PurePosixPath(name)
        if (not isinstance(name, str) or path.is_absolute() or '\\' in name or ':' in name
                or any(part in ('', '.', '..') for part in name.split('/')) or str(path) != name
                or path.suffix != '.py' or name not in required):
            raise ValueError('preflight source path is outside its explicit scope')
        target = BASE.joinpath(*path.parts)
        for entry in (target, *target.parents):
            if entry.is_symlink() or (hasattr(entry, 'is_junction') and entry.is_junction()):
                raise ValueError('preflight source cannot use links')
        _regular(target)
        if sha256(target.read_bytes()).hexdigest() != digest:
            raise ValueError('preflight source hash is stale')
    return hashes


def _imports():
    """Finish native-library imports before the strictly non-sampling operation."""
    from ibme.hibe.chkp import CHKPHIBE, CHKPPublicKey, CHKPMasterSecret, CHKPLevel1SecretKey, research_params
    from ibme.lattice.chkp.extended_gpv import ExtendedGPV
    from ibme.lattice.chkp.finite_gpv import FirstFiniteGPV
    from ibme.lattice.chkp.finite_randbasis import FirstFiniteRandBasis
    from ibme.lattice.chkp.root_generation import MP12RootGenerator
    return locals()


@contextmanager
def _no_entropy(api):
    from ibme.core.randomness import SecureRandom, DeterministicRandom
    guard = {'forbidden_calls': 0}
    def forbidden(*args, **kwargs):
        guard['forbidden_calls'] += 1
        raise AssertionError('entropy or generation is forbidden during explicit recovery')
    targets = [(SecureRandom, 'read'), (DeterministicRandom, 'read'), (os, 'urandom'),
               (secrets, 'token_bytes'), (random, '_urandom'),
               (random.SystemRandom, 'getrandbits'), (random.SystemRandom, 'random'),
               (api['CHKPHIBE'], 'setup'), (api['CHKPHIBE'], 'derive'),
               (api['MP12RootGenerator'], 'generate'), (api['FirstFiniteRandBasis'], 'sample'),
               (api['FirstFiniteGPV'], 'sample'), (api['ExtendedGPV'], 'sample')]
    with ExitStack() as stack:
        for owner, name in targets:
            stack.enter_context(patch.object(owner, name, forbidden))
        yield guard


def _state_case(public, master, failed, cached, receiver, sender):
    """Read-only primitive introspection, confined to this explicit research tool."""
    if (master.public_key.to_bytes() != public.to_bytes() or failed.public_key.to_bytes() != public.to_bytes()
            or cached.public_key.to_bytes() != public.to_bytes()
            or failed.identity != receiver or cached.identity != receiver):
        raise ValueError('source context or receiver mismatch')
    # Constructors have already validated complete bases, canonical scopes and
    # fixed preimages. These checks additionally pin the ONLY permitted history.
    if set(master.state._entries) != {receiver} or master.state._entries[receiver] is not cached.state:
        raise ValueError('source master must contain exactly the cached Bob parent')
    if cached.state._seeds._entries:
        raise ValueError('successful cached parent already contains child state')
    if failed.state._seeds._entries != {sender: None}:
        raise ValueError('failed snapshot must contain exactly Alice FAILED and no READY')
    if (cached.state.scope.to_bytes() != failed.state.scope.to_bytes()
            or cached.state._basis.basis_rows != failed.state._basis.basis_rows):
        raise ValueError('failed parent changed beyond its single zero-entropy tombstone')


def _prepare(api, blobs, receipts):
    from experiments.research.chkp_lifecycle import NoEntropy
    from ibme.protocol.hybrid_hibe import encoded_identity, HybridLimits
    public = api['CHKPPublicKey'].from_bytes(blobs['public.bin'])
    master = api['CHKPMasterSecret'].from_bytes(blobs['master.bin'])
    failed = api['CHKPLevel1SecretKey'].from_bytes(blobs['parent.bin'])
    if public.params != api['research_params']():
        raise ValueError('recovery is limited to the frozen research profile')
    backend, limits = api['CHKPHIBE'](), HybridLimits(backend_id=b'chkp')
    receiver, sender = encoded_identity(b'Bob', limits, b'P'), encoded_identity(b'Alice', limits, b'C')
    cached = backend.extract(master, receiver, rng=NoEntropy())
    _state_case(public, master, failed, cached, receiver, sender)
    if (receipts['setup'].get('root_dimension') != public.params.m
            or receipts['setup'].get('public_bytes') != len(blobs['public.bin'])
            or receipts['parent'].get('parent_dimension') != 2*public.params.m
            or receipts['parent'].get('parent_bytes') != len(cached.to_bytes())):
        raise ValueError('source measurements differ from decoded objects')
    return public, master, cached, receiver, sender


def _copy_verified_parent(api, objects, blobs):
    from experiments.research.chkp_lifecycle import NoEntropy
    public, master, parent, receiver, sender = objects
    output = {'public.bin': public.to_bytes(), 'master.bin': master.to_bytes(), 'parent.bin': parent.to_bytes()}
    if output['public.bin'] != blobs['public.bin'] or output['master.bin'] != blobs['master.bin']:
        raise ValueError('recovery changed successful public/root/master bytes')
    restored_master = api['CHKPMasterSecret'].from_bytes(output['master.bin'])
    restored_parent = api['CHKPLevel1SecretKey'].from_bytes(output['parent.bin'])
    cached = api['CHKPHIBE']().extract(restored_master, receiver, rng=NoEntropy())
    if cached.to_bytes() != output['parent.bin'] or restored_parent.to_bytes() != output['parent.bin']:
        raise ValueError('copied parent failed zero-entropy canonical restoration')
    return output


def _directory(value):
    path = Path(value).absolute()
    for entry in (path, *path.parents):
        if entry.is_symlink() or (hasattr(entry, 'is_junction') and entry.is_junction()):
            raise ValueError('recovery directories cannot use links')
    return private_directory(path)


def _run_locked(source, output):
    if sorted(path.name for path in source.glob('*.pending')) != ['leaf.pending']:
        raise ValueError('source must have exactly the original leaf pending marker')
    if any((source/name).exists() for name in ('child.bin', 'capsule.bin', 'roundtrip.json', 'resume.json')):
        raise ValueError('source already has downstream or migrated results')
    before = _inventory(source)
    if not set(INPUTS).issubset(before):
        raise ValueError('source evidence is incomplete')
    blobs = {}
    for name in INPUTS:
        if (source/name).stat().st_size > 16*2**20:
            raise ValueError('source object exceeds the bounded recovery input')
        blobs[name] = (source/name).read_bytes()
        if sha256(blobs[name]).hexdigest() != before[name]:
            raise ValueError('source changed while reading its evidence')
    receipts, diagnosis = _validate_evidence(blobs)
    preflight_hashes = _validate_preflight(blobs, source)
    # No pre-existing directory can be resumed or overwritten, even if empty.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    marker = output/'resume.pending'
    write(marker, b'Explicit research migration pending. No automatic retry.\n')
    started = time.monotonic()
    result = dict(schema=SCHEMA, phase='resume', passed=False, security_claim='none',
        backend_admitted=False, parameters_are_formal=False, entropy_bytes=0,
        source_label=source.name, recovery='copy-successful-parent-after-zero-entropy-preflight-failure',
        source_receipt_sha256={name: before[name] for name in ('setup.json', 'parent.json', 'leaf.json', DIAGNOSTIC, PREFLIGHT)},
        original_leaf_failure=receipts['leaf'], original_diagnosis=diagnosis)
    try:
        with key_issuance_lock(output, timeout=0):
            _dump(output/'resume-intent.private.json', dict(schema=SCHEMA, source_files_sha256=before,
                  source_directory=str(source), source_lock_file_excluded=LOCK_FILE, public_ledger='resume.json'))
            code_hashes = preflight_hashes | {name: sha256((BASE/name).read_bytes()).hexdigest() for name in CODE_INPUTS}
            api = _imports()
            with _no_entropy(api) as guard:
                objects = _prepare(api, blobs, receipts)
                snapshots = _copy_verified_parent(api, objects, blobs)
            if guard['forbidden_calls'] != 0:
                raise AssertionError('forbidden recovery operation was attempted')
            if _inventory(source) != before:
                raise ValueError('source changed during the zero-entropy recovery')
            for name, data in snapshots.items():
                write(output/name, data)
            for phase in ('setup', 'parent'):
                receipt = dict(receipts[phase], reused_actual_result=True, executed_this_run=False,
                    this_run_entropy_bytes=0, source_receipt_sha256=before[phase+'.json'],
                    source_relative=source.relative_to(BASE).as_posix(), recovery_ledger='resume.json')
                _dump(output/(phase+'.json'), receipt)
            if _inventory(source) != before:
                raise ValueError('source changed before migration publication')
            if {name: sha256((BASE/name).read_bytes()).hexdigest() for name in code_hashes} != code_hashes:
                raise ValueError('implementation changed during recovery')
            result.update(passed=True, source_unchanged=True, complete_leaf_preflight_verified=True,
                full_256_target_entropy_budget_verified=True, preflight_executed_this_run=False,
                ready_for_first_leaf_attempt=True, zero_entropy_restore=True,
                root_and_master_bytes_unchanged=True, cached_parent_bytes_unchanged=True,
                public_and_parameters_unchanged=True, old_tombstone_preserved=True,
                new_sampling_performed=False, basis_postprocessing_performed=False,
                forbidden_calls=0, source_code_sha256=code_hashes)
    except BaseException as exc:
        result.update(passed=False, failure_type=type(exc).__name__)
        # No arithmetic exception message or traceback is public.
    result['seconds'] = time.monotonic()-started
    _dump(output/'resume.json', result)
    if result['passed']:
        marker.unlink()
        sync_directory(output)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['passed'] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--directory', help='must be SOURCE-resumed; defaults to that unique branch')
    args = parser.parse_args(argv)
    try:
        source = _directory(args.source)
        expected_output = source.with_name(source.name + '-resumed')
        output = _directory(args.directory or expected_output)
        if not source.is_dir() or output.exists() or output == source:
            raise ValueError('source must exist and recovery output must be fresh')
        if output != expected_output:
            raise ValueError('each source has only one explicitly named recovery branch')
        # Acquiring the standard lock must not create/modify a source file.
        _regular(source/LOCK_FILE)
        if (source/LOCK_FILE).stat().st_size < 1:
            raise ValueError('source permanent lock must already be initialized')
        with key_issuance_lock(source, timeout=0):
            return _run_locked(source, output)
    except (ValueError, OSError, StateBusyError) as exc:
        # Paths/messages from untrusted inputs are not echoed.
        parser.error('recovery rejected: ' + type(exc).__name__)


if __name__ == '__main__':
    raise SystemExit(main())
