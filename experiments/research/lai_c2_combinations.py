"""Bounded C2 composition runs with real, uncached public protocol calls.

Four suites share one freshly sampled HIBE root and two level-one keys. Each
suite has its own IBS root and sender. Every identity case runs in a fresh
interpreter and performs the unchanged Lai Derive; no prepared leaf or mock is
used. Private objects and diagnostics stay in a new local directory. This is
one functional trial per suite, not a repeated or independent-root benchmark.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from experiments.research.runtime_metrics import environment, measured_phase

ROOT = Path(__file__).resolve().parents[2]
SENDER, RECEIVER, OTHER_RECEIVER, OTHER_SENDER = (c * 64 for c in (b'A', b'B', b'C', b'E'))
MESSAGE = bytes(range(32))
IDENTITY_CASES = {
    'honest': (RECEIVER, SENDER),
    'wrong_sender': (RECEIVER, OTHER_SENDER),
    'wrong_receiver': (OTHER_RECEIVER, SENDER),
    'both_wrong': (OTHER_RECEIVER, OTHER_SENDER),
}
FAMILIES = {
    'mldsa44': ('cert-ml-dsa', 'ml-dsa-44', 'reference'),
    'falcon512': ('cert-falcon', 'falcon-padded-512', 'reference'),
    'srgg-I': ('srgg2025-paper', 'PARAM-I', 'compact'),
    'sageloli-I': ('sageloli-rsis', 'PARAM-I', 'reference'),
}


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def write_new(path, value):
    raw = value if type(value) is bytes else (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


def providers():
    found = {}
    for module in list(sys.modules.values()):
        value = getattr(module, '__file__', None)
        if value and str(value).endswith('.py'):
            path = Path(value).resolve()
            if path.is_relative_to(ROOT):
                found[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def plans():
    from ibme.assembly import default_registry, make_suite, validate_suite
    version = default_registry().get('hibe', 'lai-ideal-hibe').version
    limits = dict(backend_id=version, identity_max_bytes=64,
                  max_payload_bytes=8 * 2**20, max_capsule_bytes=4 * 2**20)
    result = {}
    for name, (ibs, preset, fmt) in FAMILIES.items():
        config = make_suite(hibe='lai-ideal-hibe', hibe_params='target-research',
                            ibs=ibs, ibs_params=preset, signature_format=fmt,
                            transport='hybrid', protocol='byteauth-v1', hybrid_limits=limits)
        report = validate_suite(config)
        require(report.ok, name + ': preflight failed')
        result[name] = dict(suite=config.to_dict(), suite_digest=config.digest,
                            preflight=report.to_dict())
    return result


def check(checks, label, condition):
    checks.append(dict(name=label, passed=bool(condition)))
    require(condition, label)


def prepare(directory, commit):
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.core.encoding import encode_message
    from ibme.core.errors import SerializationError
    from ibme.core.lamport_ots import generate_lamport_key
    from ibme.core.randomness import SecureRandom
    from ibme.protocol.baseline import BOTTOM, MasterSecret, PublicKey, ReceiverKey, SenderKey

    selections = plans()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows, phases = {}, []
    report = dict(schema='LAI-C2-COMPOSITIONS/1', source_commit=commit,
                  environment=environment(), hibe_root_count=1, receiver_key_count=2,
                  repetitions_per_suite=1, message_bytes=32, identity_bytes=64,
                  inner_identity_bytes=86, inner_payload_bytes=32,
                  randomness='OS CSPRNG; no deterministic test stream',
                  shared_hibe_root=True, shared_level1_keys=True, leaf_cache=False,
                  security_claim='none', backend_admitted=False, parameters_are_formal=False,
                  random_oracle_scope='As described by the selected primitive contracts; no new proof.',
                  phases=phases, suites=rows)
    first = build_runtime(SuiteConfig.from_dict(next(iter(selections.values()))['suite']))
    with measured_phase('shared-hibe-setup', phases):
        hpk, hmsk = first.hibe.setup(first.hibe_params)
    receivers = {}
    for name, identity in (('receiver', RECEIVER), ('other-receiver', OTHER_RECEIVER)):
        with measured_phase('shared-' + name + '-extract', phases):
            receivers[name] = ReceiverKey(first.hibe.extract(hmsk, identity))
        write_new(directory / (name + '.bin'), receivers[name].to_bytes())
    report['shared_object_bytes'] = dict(hpk=len(hpk.to_bytes()), hmsk=len(hmsk.to_bytes()),
                                        **{k: len(v.to_bytes()) for k, v in receivers.items()})

    for name, plan in selections.items():
        print('prepare ' + name, flush=True)
        work = directory / name
        work.mkdir(mode=0o700)
        config = SuiteConfig.from_dict(plan['suite'])
        runtime = build_runtime(config)
        require(runtime.hibe_params == first.hibe_params, 'identical HIBE configuration required for root reuse')
        proto = runtime.proto
        row = dict(**plan, phases=[], checks=[])
        rows[name] = row
        write_new(work / 'suite.json', plan['suite'])
        with measured_phase('ibs-setup', row['phases']):
            ipk, imsk = runtime.ibs.setup(runtime.ibs_params)
        public, master = PublicKey(hpk, ipk), MasterSecret(hmsk, imsk)
        with measured_phase('sender-key', row['phases']):
            sender = proto.skgen(master, SENDER)
        with measured_phase('encrypt', row['phases']):
            cipher = proto.encrypt(public, sender, RECEIVER, MESSAGE)
            wire = cipher.to_bytes()
        blobs = dict(public=public.to_bytes(), master=master.to_bytes(), sender=sender.to_bytes(), ciphertext=wire)
        for label, raw in blobs.items():
            write_new(work / (label + '.bin'), raw)
        row['object_bytes'] = {k: len(v) for k, v in blobs.items()}
        d = runtime.decoders
        with measured_phase('restore-and-bind-objects', row['phases']):
            restored_public = PublicKey.from_bytes(blobs['public'], d['hpk'], d['ipk'])
            restored_master = MasterSecret.from_bytes(blobs['master'], d['hmsk'], d['imsk'])
            restored_sender = SenderKey.from_bytes(blobs['sender'], d['sk'])
            runtime.validate_master(restored_public, restored_master)
            runtime.validate_sender(restored_public, restored_sender)
            for label, obj in (('public', restored_public), ('master', restored_master), ('sender', restored_sender)):
                check(row['checks'], label + '_restore', obj.to_bytes() == blobs[label])
        check(row['checks'], 'ciphertext_canonical', proto.load_ciphertext(wire).to_bytes() == wire)

        # Observe the public method and always forward to the unchanged sampler.
        # Outer/wire rejection must finish before expensive leaf generation.
        calls = []
        original = runtime.hibe.inner_backend.derive
        def counted(*args, **kwargs):
            calls.append(1)
            return original(*args, **kwargs)
        runtime.hibe.inner_backend.derive = counted
        with measured_phase('outer-and-wire-negatives', row['phases']):
            for field in ('context', 'inner_bytes', 'signature'):
                raw = getattr(cipher, field)
                bad = replace(cipher, **{field: raw[:-1] + bytes([raw[-1] ^ 1])})
                check(row['checks'], 'byteauth_' + field,
                      proto.decrypt(public, receivers['receiver'], SENDER, bad) is BOTTOM)
            other_ots = generate_lamport_key(rng=SecureRandom())
            check(row['checks'], 'byteauth_ots_key', proto.decrypt(
                public, receivers['receiver'], SENDER, replace(cipher, ots_key=other_ots.public_key)) is BOTTOM)
            for label, raw in (('truncated', wire[:-1]), ('appended', wire + b'\0'),
                               ('duplicate', wire + wire), ('version', b'?' + wire[1:])):
                try:
                    proto.load_ciphertext(raw)
                except SerializationError:
                    rejected = True
                else:
                    rejected = False
                check(row['checks'], label + '_loader', rejected)
                check(row['checks'], label + '_decrypt',
                      proto.decrypt(public, receivers['receiver'], SENDER, raw) is BOTTOM)
        check(row['checks'], 'outer_rejection_without_derive', not calls)
        runtime.hibe.inner_backend.derive = original

        # This is a distinct public IBS probe, not a claim about which layer
        # rejected a tampered outer ciphertext or its embedded signature size.
        with measured_phase('standalone-ibs-negatives', row['phases']):
            signed = encode_message(RECEIVER, b'C2-composition-signature-probe')
            signature = runtime.ibs.sign(sender.signing_key, signed)
            raw = signature.to_bytes()
            row['standalone_signature_bytes'] = len(raw)
            signature = runtime.ibs.load_signature(public.ipk, raw)
            check(row['checks'], 'ibs_honest', runtime.ibs.verify(public.ipk, SENDER, signed, signature) is True)
            check(row['checks'], 'ibs_wrong_message', runtime.ibs.verify(public.ipk, SENDER, signed + b'!', signature) is False)
            check(row['checks'], 'ibs_wrong_identity', runtime.ibs.verify(public.ipk, OTHER_SENDER, signed, signature) is False)
            for label, guess in (('ibs_changed_signature', raw[:-1] + bytes([raw[-1] ^ 1])),
                                 ('ibs_random_signature', SecureRandom().read(len(raw)))):
                try:
                    guessed = runtime.ibs.load_signature(public.ipk, guess)
                except SerializationError:
                    rejected = True
                else:
                    rejected = runtime.ibs.verify(public.ipk, SENDER, signed, guessed) is False
                check(row['checks'], label, rejected)
        write_new(work / 'prepared.json', row)
    report['source_files'] = providers()
    write_new(directory / 'prepared.json', report)
    return report


def decrypt_case(directory, name, case):
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.protocol.baseline import BOTTOM, PublicKey, ReceiverKey
    work = directory / name
    protected = [work / 'suite.json', work / 'public.bin', work / 'ciphertext.bin',
                 directory / ('other-receiver.bin' if case in ('wrong_receiver', 'both_wrong') else 'receiver.bin')]
    before = [hashlib.sha256(p.read_bytes()).digest() for p in protected]
    phases, calls = [], []
    with measured_phase('restore-objects', phases):
        config = SuiteConfig.from_json(protected[0].read_bytes())
        runtime = build_runtime(config)
        d = runtime.decoders
        public = PublicKey.from_bytes(protected[1].read_bytes(), d['hpk'], d['ipk'])
        wire = protected[2].read_bytes()
        receiver = ReceiverKey.from_bytes(protected[3].read_bytes(), d['sk1'])
        require(receiver.identity == IDENTITY_CASES[case][0], 'restored receiver identity')
        require(receiver.to_bytes() == protected[3].read_bytes(), 'canonical receiver recovery')
    original = runtime.hibe.inner_backend.derive
    def observed(*args, **kwargs):
        with measured_phase('real-lai-derive', calls):
            return original(*args, **kwargs)
    runtime.hibe.inner_backend.derive = observed
    with measured_phase('complete-protocol-decrypt', phases):
        recovered = runtime.proto.decrypt(public, receiver, IDENTITY_CASES[case][1], wire)
    unchanged = before == [hashlib.sha256(p.read_bytes()).digest() for p in protected]
    passed = ((recovered == MESSAGE) if case == 'honest' else (recovered is BOTTOM))
    result = dict(suite=name, case=case, status='passed' if passed and unchanged and len(calls) == 1 else 'failed',
                  matches=(recovered == MESSAGE), bottom=(recovered is BOTTOM),
                  output_bytes=len(recovered) if type(recovered) is bytes else 0,
                  original_files_unchanged=unchanged, fresh_process=True,
                  real_derive_calls=len(calls), leaf_cache=False, phases=phases,
                  derive_phases=calls, source_files=providers())
    write_new(work / (case + '.json'), result)
    require(result['status'] == 'passed', name + ': ' + case)
    return result


def child(directory, mode, *args, timeout=1800):
    command = [sys.executable, '-m', 'experiments.research.lai_c2_combinations',
               mode, '--directory', str(directory), *args]
    label = mode + '-' + '-'.join(args).replace('/', '_')
    # Logs are private and never copied into a public receipt.
    with (directory.parent / (directory.name + '-' + hashlib.sha256(label.encode()).hexdigest()[:16] + '.log')).open('xb') as log:
        os.chmod(log.name, 0o600)
        try:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return dict(returncode=None, timed_out=True)
    return dict(returncode=process.returncode, timed_out=False)


def run(directory, commit, workers):
    require(not directory.exists(), 'choose a new private directory')
    directory.parent.mkdir(parents=True, exist_ok=True)
    setup = child(directory, 'prepare', '--source-commit', commit, timeout=1800)
    require(setup['returncode'] == 0, 'preparation failed; preserve private directory/log')
    report = json.loads((directory / 'prepared.json').read_bytes())
    report['concurrent_decrypt_limit'] = workers
    report['preparation_process'] = setup
    with ThreadPoolExecutor(max_workers=workers) as pool:
        tasks = {pool.submit(child, directory, 'decrypt', '--suite', name, '--case', case): (name, case)
                 for case in IDENTITY_CASES for name in FAMILIES}
        for future in as_completed(tasks):
            name, case = tasks[future]
            result = future.result()
            path = directory / name / (case + '.json')
            row = json.loads(path.read_bytes()) if path.exists() else dict(status='failed', no_receipt=True)
            row['process'] = result
            report['suites'][name].setdefault('identity_cases', {})[case] = row
            print(json.dumps(dict(suite=name, case=case, status=row['status'], process=result)), flush=True)
    report['status'] = ('passed' if all(
        set(row.get('identity_cases', {})) == set(IDENTITY_CASES)
        and all(check['passed'] for check in row['checks'])
        and all(case['status'] == 'passed' and case['process']['returncode'] == 0
                for case in row['identity_cases'].values())
        for row in report['suites'].values()) else 'failed')
    report['limitations'] = [
        'One shared HIBE root; one IBS root and one 32-byte encryption per suite. No statistical failure estimate.',
        'Every identity case loads serialized objects in a new process and performs one real uncached Lai Derive.',
        'Recovery consumes fresh sampling entropy; no zero-entropy leaf recovery is claimed.',
        'Standalone IBS negatives use an additional signature, not the signature extracted from the ciphertext.',
        'No valid-outer/invalid-inner forgery or empty-message C2 test is included in this bounded run.',
        'Parallel timings with shared HIBE preparation are observations, not independent-root performance rankings.',
        'C2 and the IBS presets retain their documented research limitations; functional tests are not security proofs.',
    ]
    write_new(directory / 'report.json', report)
    require(report['status'] == 'passed', 'one or more composition cases failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'run', 'prepare', 'decrypt'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--source-commit')
    parser.add_argument('--suite', choices=tuple(FAMILIES))
    parser.add_argument('--case', choices=tuple(IDENTITY_CASES))
    parser.add_argument('--workers', type=int, choices=range(1, 7), default=4)
    args = parser.parse_args()
    if args.mode in ('run', 'prepare') and not re.fullmatch('[0-9a-f]{40}', args.source_commit or ''):
        parser.error('generation requires a fixed 40-digit source commit')
    if args.mode == 'plan':
        write_new(args.directory, dict(mode='preflight-only', execution='not_executed', suites=plans()))
    elif args.mode == 'run':
        run(args.directory.resolve(), args.source_commit, args.workers)
    elif args.mode == 'prepare':
        prepare(args.directory.resolve(), args.source_commit)
    elif not args.suite or not args.case:
        parser.error('decrypt requires suite and case')
    else:
        decrypt_case(args.directory.resolve(), args.suite, args.case)


if __name__ == '__main__':
    main()
