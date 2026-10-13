"""Read-only CHKP public archive audit; neither sampling nor a security proof.

source-manifest.json has exactly: schema, source_commit (recorded Git SHA-1),
suite_digest, source_files, evidence_files. Each list is nonempty and contains
only {path, sha256}. Source paths are relative to --source-root, evidence paths
to --directory; the manifest never hashes itself. No private .bin/log files,
Git objects, external paths, or random sources are read. Hashes establish
content consistency, not provenance/authenticity or experiment reproduction.
REQUIRED_SOURCES is a fixed core coverage floor, not a complete dependency
closure proof; unrelated repository files are not dynamically required.
"""

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath
import re

from experiments.research.chkp_combination import PHASES, selected_suite, validate_receipt
from experiments.research.chkp_cli_acceptance import BASE, validate_cli_receipt

SCHEMA = 'IBME/CHKP-PUBLIC-DELIVERY/1'
DEFAULT = BASE / 'docs/research/2026-10-12-chkp-closure'
LIFECYCLE = ('setup', 'parent', 'leaf', 'roundtrip')
REQUIRED = tuple(f'evidence/{group}/{phase}.json' for group, phases in (
    ('lifecycle', LIFECYCLE), ('combination', PHASES[1:]), ('cli', ('setup', 'imported')))
    for phase in phases)
REQUIRED_SOURCES = (
    'src/ibme/hibe/chkp/backend.py', 'src/ibme/hibe/chkp/params.py', 'src/ibme/hibe/chkp/objects.py',
    'src/ibme/lattice/chkp/root_generation.py', 'src/ibme/lattice/chkp/root_basis.py',
    'src/ibme/lattice/chkp/finite_gpv.py', 'src/ibme/lattice/chkp/extended_gpv.py',
    'src/ibme/lattice/chkp/finite_randbasis.py', 'src/ibme/lattice/chkp/finite_gaussian.py',
    'src/ibme/lattice/chkp/tobasis.py', 'src/ibme/lattice/chkp/basis_reduce.py',
    'src/ibme/lattice/chkp/basis.py', 'src/ibme/lattice/chkp/identity.py',
    'src/ibme/lattice/chkp/delegation_state.py', 'src/ibme/lattice/chkp/leaf_state.py',
    'src/ibme/lattice/chkp/seed_kem.py', 'src/ibme/lattice/chkp/rounded_noise.py',
    'src/ibme/lattice/chkp/noise_budget.py', 'src/ibme/lattice/chkp/joint_parameters.py',
    'src/ibme/assembly/__init__.py', 'src/ibme/assembly/registry.py',
    'src/ibme/cli.py', 'src/ibme/cli_state.py',
    'src/ibme/protocol/hybrid_hibe.py', 'src/ibme/protocol/byteauth.py', 'src/ibme/protocol/baseline.py',
    'src/ibme/ibs/luo_module.py', 'src/ibme/ibs/luo_module_profiles.py',
    'src/ibme/ibs/luo_module_codec.py', 'src/ibme/ibs/luo_module_math.py',
    'experiments/research/chkp_lifecycle.py', 'experiments/research/chkp_combination.py',
    'experiments/research/chkp_cli_acceptance.py', 'experiments/attacks/chkp_small_dimension.py',
    'experiments/research/chkp_resume_pre_entropy.py', 'tests/test_chkp_resume_pre_entropy.py',
    'experiments/research/audit_chkp_delivery.py',
)
RESUME = 'evidence/lifecycle/resume.json'
RESUME_HISTORY = {
    'setup.json': 'evidence/lifecycle/history/setup.json',
    'parent.json': 'evidence/lifecycle/history/parent.json',
    'leaf.json': 'evidence/lifecycle/history/leaf-failed.json',
    'leaf_preflight_diagnostic_600.json': 'evidence/diagnostics/preflight-failure-gate.json',
    'leaf_full_preflight_receipt.json': 'evidence/diagnostics/preflight-complete.json',
}
REUSE_METADATA = frozenset(('reused_actual_result', 'executed_this_run', 'this_run_entropy_bytes',
                           'source_receipt_sha256', 'source_relative', 'recovery_ledger'))
HEX256 = re.compile(r'[0-9a-f]{64}\Z')
LIMIT = 16 * 2**20
FLAGS = dict(security_claim='none', backend_admitted=False, parameters_are_formal=False)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value
         and not any(ord(c) < 32 for c in value), 'invalid relative path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value
         and all(part not in ('.', '..') for part in path.parts), 'path escape or noncanonical path')
    return path


def read_bounded(root, name):
    path = root
    for part in relative(name).parts:
        path = path / part
        need(not path.is_symlink() and not getattr(path, 'is_junction', lambda: False)(),
             'manifest path contains a link or junction')
    try:
        path = path.resolve(strict=True)
    except FileNotFoundError:
        raise ValueError('missing declared file: ' + name) from None
    need(path.is_relative_to(root) and path.is_file(), 'path escapes its declared root')
    need(path.stat().st_size <= LIMIT, 'file exceeds public audit size budget')
    data = path.read_bytes()
    need(len(data) <= LIMIT, 'file exceeds public audit size budget')
    return data


def document(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda value: need(False, 'nonfinite JSON number'))
    need(type(result) is dict, 'JSON object required')
    return result


def safe_flags(value, *, required=False):
    if required:
        need(type(value) is dict and all(key in value for key in FLAGS), 'missing safety flags')
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FLAGS:
                need(type(item) is type(FLAGS[key]) and item == FLAGS[key], 'unsafe safety flag')
            safe_flags(item)
    elif isinstance(value, list):
        for item in value:
            safe_flags(item)


def manifest_files(root, entries, *, source):
    need(type(entries) is list and 0 < len(entries) <= 10000, 'nonempty bounded file list required')
    result, names = {}, set()
    for entry in entries:
        need(type(entry) is dict and set(entry) == {'path', 'sha256'}, 'invalid manifest entry')
        path = relative(entry['path'])
        name = path.as_posix()
        need(name.casefold() not in names, 'duplicate manifest path')
        names.add(name.casefold())
        need(type(entry['sha256']) is str and HEX256.fullmatch(entry['sha256']), 'invalid SHA-256')
        if source:
            need(name == 'pyproject.toml' or (len(path.parts) > 1 and path.parts[0] in
                 ('src', 'tests', 'experiments') and path.suffix == '.py'), 'source path is not allowlisted')
        else:
            need(name.casefold() != 'source-manifest.json' and path.suffix in
                 ('.json', '.md', '.txt', '.csv', '.xml', '.sha256'), 'evidence path is not public/allowlisted')
        data = read_bounded(root, name)
        need(sha256(data).hexdigest() == entry['sha256'], 'file SHA-256 mismatch: ' + name)
        result[name] = data if not source else None
    return result


def lifecycle_receipt(receipt, phase, params):
    need(receipt.get('phase') == phase and receipt.get('passed') is True
         and 'failure_type' not in receipt, 'lifecycle phase is not successful')
    need(type(receipt.get('entropy_bytes')) is int and receipt['entropy_bytes'] > 0,
         'lifecycle needs positive actual entropy count')
    seconds = receipt.get('seconds')
    need(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0,
         'lifecycle needs finite timing')
    need(receipt.get('randomness') == 'system CSPRNG', 'lifecycle RNG is not the actual research source')
    dimensions = {'setup': ('root_dimension', params.m), 'parent': ('parent_dimension', 2*params.m),
                  'leaf': ('leaf_dimension', params.leaf_dimension)}
    if phase in dimensions:
        key, expected = dimensions[phase]
        need(type(receipt.get(key)) is int and receipt[key] == expected, 'lifecycle dimension mismatch')
    if phase == 'leaf':
        need(type(receipt.get('targets')) is int and receipt['targets'] == 256, 'leaf must have 256 targets')
    if phase != 'roundtrip':
        return
    need(all(receipt.get(key) is True for key in ('raw_roundtrip', 'zero_entropy_restore',
         'public_attack_matches_seed')), 'roundtrip/restore/attack check missing')
    from ibme.hibe.chkp import ciphertext_size
    need(type(receipt.get('ciphertext_bytes')) is int
         and receipt['ciphertext_bytes'] == ciphertext_size(params, 32), '32-byte capsule size mismatch')
    attack, digest = receipt.get('public_attack'), receipt.get('actual_seed_sha256')
    need(type(attack) is dict and type(digest) is str and HEX256.fullmatch(digest), 'missing attack/seed digest')
    safe_flags(attack, required=True)
    need(attack.get('seed_bits') == 256 and attack.get('n') == params.n and attack.get('q') == params.q
         and attack.get('preamble_coordinates') == params.leaf_dimension, 'attack profile or 32-byte seed mismatch')
    hashes = attack.get('recovered_seed_sha256')
    need(type(hashes) is list and hashes and all(type(v) is str and HEX256.fullmatch(v) for v in hashes)
         and len(set(hashes)) == len(hashes) and digest in hashes, 'actual seed digest was not recovered')
    need(type(attack.get('distinct_seed_candidates')) is int
         and attack['distinct_seed_candidates'] == len(hashes), 'attack candidate count mismatch')
    need(attack.get('status') == 'candidate_found'
         and attack.get('unique_seed_candidate') is (len(hashes) == 1), 'attack result status mismatch')
    radius, count = attack.get('finite_noise_radius'), attack.get('enumerated_error_tuples')
    need(type(radius) is int and radius == 36 and type(count) is int and count == (2*radius+1)**params.n,
         'attack enumeration does not cover the frozen finite support')
    need(type(attack.get('max_candidates')) is int and count <= attack['max_candidates'] <= 1000000,
         'attack exceeds its explicit budget')
    need(type(attack.get('preamble_candidates')) is int and type(attack.get('surviving_candidates')) is int
         and len(hashes) <= attack['surviving_candidates'] <= attack['preamble_candidates'] <= count,
         'attack surviving count mismatch')
    need(all(attack.get(key) is False for key in ('private_state_loaded', 'private_seed_input', 'randomness_used')),
         'attack must use only public deterministic inputs')


def resume_receipts(evidence, params):
    """Check an archived explicit migration, never open its private binding path."""
    phases = {phase: document(evidence[f'evidence/lifecycle/{phase}.json']) for phase in ('setup', 'parent')}
    indicated = (RESUME in evidence or any(REUSE_METADATA & set(value) for value in phases.values())
                 or any(RESUME_HISTORY[name] in evidence for name in ('setup.json', 'parent.json', 'leaf.json')))
    if not indicated:
        return False
    need({RESUME, *RESUME_HISTORY.values()} <= set(evidence), 'reused lifecycle omits public recovery history')
    from experiments.research.chkp_resume_pre_entropy import (
        SCHEMA as RESUME_SCHEMA, PREFLIGHT, PREFLIGHT_GATES, _validate_evidence)
    resume = document(evidence[RESUME])
    safe_flags(resume, required=True)
    need(resume.get('schema') == RESUME_SCHEMA and resume.get('phase') == 'resume'
         and resume.get('passed') is True and 'failure_type' not in resume, 'recovery receipt is not successful')
    need(all(resume.get(key) is True for key in (
        'source_unchanged', 'complete_leaf_preflight_verified', 'full_256_target_entropy_budget_verified',
        'ready_for_first_leaf_attempt', 'zero_entropy_restore', 'root_and_master_bytes_unchanged',
        'cached_parent_bytes_unchanged', 'public_and_parameters_unchanged', 'old_tombstone_preserved')),
        'recovery lacks unchanged-state, preflight or failure-preservation checks')
    need(all(resume.get(key) is False for key in (
        'new_sampling_performed', 'basis_postprocessing_performed', 'preflight_executed_this_run')),
        'recovery must distinguish copied history from a fresh sampled lifetime')
    need(all(type(resume.get(key)) is int and resume[key] == 0 for key in ('entropy_bytes', 'forbidden_calls')),
         'recovery consumed entropy or attempted a forbidden operation')
    need(resume.get('recovery') == 'copy-successful-parent-after-zero-entropy-preflight-failure',
         'unknown research recovery policy')
    seconds = resume.get('seconds')
    need(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0, 'invalid recovery timing')
    hashes = {name: sha256(evidence[path]).hexdigest() for name, path in RESUME_HISTORY.items()}
    need(resume.get('source_receipt_sha256') == hashes, 'recovery source receipt hashes differ from archived history')
    blobs = {name: evidence[path] for name, path in RESUME_HISTORY.items()}
    originals, diagnosis = _validate_evidence(blobs)
    need(resume.get('original_leaf_failure') == originals['leaf'] and resume.get('original_diagnosis') == diagnosis,
         'recovery changed or omitted the original failure/diagnosis')
    label = resume.get('source_label')
    need(type(label) is str and re.fullmatch(r'[A-Za-z0-9_-]+', label), 'invalid recovery source label')
    origin = 'test-results/' + label
    for phase, receipt in phases.items():
        original = originals[phase]
        safe_flags(original, required=True)
        lifecycle_receipt(original, phase, params)
        need(not (REUSE_METADATA & set(original)), 'recovery history itself claims another migration')
        need(receipt.get('reused_actual_result') is True and receipt.get('executed_this_run') is False
             and type(receipt.get('this_run_entropy_bytes')) is int and receipt['this_run_entropy_bytes'] == 0
             and receipt.get('recovery_ledger') == 'resume.json' and receipt.get('source_relative') == origin
             and receipt.get('source_receipt_sha256') == hashes[phase+'.json'], 'reused phase provenance mismatch')
        need({key: value for key, value in receipt.items() if key not in REUSE_METADATA} == original,
             'reused phase changed the original measurements or result')
    preflight = document(blobs[PREFLIGHT])
    safe_flags(preflight)
    need(preflight.get('schema') == 'ibme.chkp.leaf-preflight.v1'
         and all(preflight.get(key) is True for key in ('passed', 'source_parent_unchanged',
             'cache_geometry_old_new_ast_unchanged'))
         and all(preflight.get(key) is False for key in ('sample_called', 'state_mutation_called', 'gso_recomputed')),
         'archived complete preflight did not pass its non-sampling route')
    need(type(preflight.get('targets')) is int and preflight['targets'] == 256
         and type(preflight.get('entropy_bytes')) is int and preflight['entropy_bytes'] == 0,
         'complete preflight lacks the zero-entropy 256-target gate')
    gates = preflight.get('all_gates')
    need(type(gates) is dict and set(gates) == PREFLIGHT_GATES and all(value is True for value in gates.values()),
         'archived complete preflight omits or fails a required gate')
    need(preflight.get('source_parent_relative') == origin+'/parent.bin'
         and preflight.get('private_binding_relative') == origin+'/leaf_full_preflight_binding.json',
         'complete preflight belongs to another source lifetime')
    recorded, earlier = resume.get('source_code_sha256'), preflight.get('source_sha256')
    need(type(recorded) is dict and type(earlier) is dict and earlier
         and preflight.get('source_relative') == sorted(earlier)
         and all(recorded.get(name) == digest for name, digest in earlier.items()),
         'recovery and preflight disagree on their source versions')
    # Historical raw file hashes may differ from Git's canonical LF bytes.
    # Keep them unchanged and check their cross-receipt agreement; do not claim
    # that auditing today's manifest verifies historical execution bytecode.
    # Historical ignored diagnostic scripts/private binding are never opened.
    required = {name for name in REQUIRED_SOURCES if name.startswith('src/ibme/')}
    need(required <= set(earlier) and 'experiments/research/chkp_resume_pre_entropy.py' in recorded,
         'recovery/preflight source record omits core implementations')
    for name, digest in recorded.items():
        need(relative(name).suffix == '.py' and type(digest) is str and HEX256.fullmatch(digest),
             'invalid historical source hash record')
    return True


def audit(directory=DEFAULT, source_root=BASE):
    result = dict(schema=SCHEMA, passed=False, errors=[], phases_checked=0, source_files_checked=0,
                  evidence_files_checked=0, experiments_rerun=False, private_state_read=False,
                  required_source_coverage_complete=False, source_dependency_closure_proved=False,
                  resumed_lifetime=False, historical_failure_preserved=False,
                  historical_source_bytes_verified=False,
                  source_commit_verified=False, **FLAGS,
                  limitation='Public archive consistency only; not authenticity, reproduction, or a security proof.')
    try:
        root, sources = Path(directory).resolve(strict=True), Path(source_root).resolve(strict=True)
        need(root.is_dir() and sources.is_dir(), 'audit roots must be directories')
        manifest = document(read_bounded(root, 'source-manifest.json'))
        need(set(manifest) == {'schema', 'source_commit', 'suite_digest', 'source_files', 'evidence_files'}
             and manifest['schema'] == SCHEMA, 'unknown or incomplete manifest schema')
        need(type(manifest['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', manifest['source_commit']),
             'recorded source commit must be a Git SHA-1')
        suite = selected_suite()
        need(manifest['suite_digest'] == suite.digest, 'manifest differs from the frozen suite')
        evidence = manifest_files(root, manifest['evidence_files'], source=False)
        need(set(REQUIRED) <= set(evidence), 'manifest omits required phase receipts')
        result['evidence_files_checked'] = len(evidence)
        source_files = manifest_files(sources, manifest['source_files'], source=True)
        result['source_files_checked'] = len(source_files)
        missing = sorted(set(REQUIRED_SOURCES) - set(source_files))
        need(not missing, 'manifest omits required core sources: ' + ', '.join(missing))
        result['required_source_coverage_complete'] = True
        from ibme.hibe.chkp import research_params
        params = research_params()
        for name in REQUIRED:
            receipt = document(evidence[name])
            safe_flags(receipt, required=True)
            group, phase = PurePosixPath(name).parts[1], PurePosixPath(name).stem
            if group == 'lifecycle':
                lifecycle_receipt(receipt, phase, params)
            elif group == 'combination':
                need('failure_type' not in receipt and type(receipt.get('repetition_count')) is int
                     and receipt['repetition_count'] == 1,
                     'combination failure/repetition mismatch')
                validate_receipt(receipt, phase, suite)
            else:
                need(type(receipt.get('repetition_count')) is int and receipt['repetition_count'] == 1,
                     'CLI repetition count mismatch')
                # Provenance path is compared lexically, never opened. In
                # particular this must not call ready_cli_receipt/private IO.
                provenance = receipt.get('provenance', {})
                need(type(provenance) is dict, 'CLI provenance object required')
                rel = relative(provenance.get('source_relative', 'test-results/unused-setup-source'))
                need(len(rel.parts) > 1 and rel.parts[0] == 'test-results', 'invalid CLI source provenance')
                validate_cli_receipt(receipt, phase, suite, BASE.joinpath(*rel.parts))
            result['phases_checked'] += 1
        resumed = resume_receipts(evidence, params)
        result.update(resumed_lifetime=resumed, historical_failure_preserved=resumed)
        result.update(passed=True, suite_digest=suite.digest, source_commit=manifest['source_commit'], seed_bytes=32)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        result['errors'].append(str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default=str(DEFAULT))
    parser.add_argument('--source-root', default=str(BASE))
    args = parser.parse_args(argv)
    result = audit(args.directory, args.source_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
