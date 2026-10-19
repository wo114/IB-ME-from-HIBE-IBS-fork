"""Exact-suite, fresh-process CLI supplement for the research report.

Run from an installed wheel outside the checkout. Private objects and full CLI
diagnostics stay in an exclusive directory; public receipts contain no keys or
plaintext. Each command uses a new process. Failed directories are never retried.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ALICE, BOB, CAROL, EVE = (c * 64 for c in 'ABCE')


def require(value, message):
    if not value:
        raise ValueError(message)


def write_new(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


def setup_arguments(suite, state):
    from ibme.assembly import SuiteConfig
    require(suite.get('security_claim') == 'none' and suite.get('backend_admitted') is False
            and suite.get('parameters_are_formal') is False and suite.get('allow_mock') is False,
            'real research suite required')
    SuiteConfig.from_dict(suite)
    args = ['setup', '--state', str(state)]
    for name in ('hibe', 'ibs', 'hibe_params', 'ibs_params', 'transport', 'protocol',
                 'signature_format', 'hybrid_limits'):
        value = suite[name]
        args.extend(['--' + name.replace('_', '-'), json.dumps(value) if isinstance(value, dict) else value])
    return args


def validate_lengths(lengths, capacity):
    require(bool(lengths) and len(set(lengths)) == len(lengths)
            and all(type(n) is int and 0 <= n <= capacity for n in lengths), 'invalid message lengths')


def validate_command(row, *, expected, zero):
    require(row['code'] == expected and row['exception'] is None, 'failed CLI command')
    if zero:
        require(row['entropy_reads'] == 0 and row['entropy_bytes'] == 0, 'zero-entropy command consumed entropy')


def merge_providers(merged, entries, *, prefix):
    prefix = prefix.resolve()
    for value in entries.values():
        try:
            relative = Path(value['path']).resolve().relative_to(prefix).as_posix()
        except ValueError as exc:
            raise ValueError('project provider outside installed prefix') from exc
        require(relative not in merged or merged[relative] == value['sha256'], 'project provider changed')
        merged[relative] = value['sha256']


def snapshot(state):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in state.iterdir()
            if p.is_file() and p.suffix in ('.bin', '.json')}


def providers():
    found = {}
    for name, module in list(sys.modules.items()):
        path = getattr(module, '__file__', None)
        if path and path.endswith('.py') and (name.startswith(('ibme.', 'experiments.research.')) or name == '__main__'):
            path = Path(path).resolve()
            found[name] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return found


def inner_signature_probe(state, rows):
    """Use CLI consistency readers, then only opaque public protocol APIs."""
    from experiments.research.runtime_metrics import measured_phase
    from ibme.assembly import SuiteConfig, build_runtime
    from ibme.cli import _read_state_object, _sender_key_path, _receiver_key_path
    from ibme.core.encoding import encode_bytes, encode_message
    from ibme.core.lamport_ots import generate_lamport_key
    from ibme.core.randomness import SecureRandom
    from ibme.protocol.baseline import BOTTOM, PublicKey, SenderKey, ReceiverKey, Ciphertext, DOMAIN_SIGNATURE
    from ibme.protocol.byteauth import authenticate_inner, encode_bound_message
    before = snapshot(state)
    with measured_phase('restore-cli-objects', rows):
        meta = json.loads((state / 'state.json').read_bytes())
        runtime = build_runtime(SuiteConfig.from_dict(meta['suite']))
        d = runtime.decoders
        public = PublicKey.from_bytes(_read_state_object(state / 'mpk.bin', meta, 'mpk'), d['hpk'], d['ipk'])
        sender = SenderKey.from_bytes(_read_state_object(_sender_key_path(state, ALICE.encode()), meta, 'sender'), d['sk'])
        receiver = ReceiverKey.from_bytes(_read_state_object(_receiver_key_path(state, BOB.encode()), meta, 'receiver'), d['sk1'])
        runtime.validate_sender(public, sender)
        runtime.validate_receiver(public, receiver)
    with measured_phase('construct-valid-outer-invalid-inner', rows):
        ots = generate_lamport_key(rng=SecureRandom())
        old = encode_bound_message(ots.public_key.commitment(), b'original probe message')
        altered = encode_bound_message(ots.public_key.commitment(), b'altered probe message')
        signature = runtime.ibs.sign(sender.signing_key, encode_message(BOB.encode(), old))
        raw = signature.to_bytes()
        restored = runtime.ibs.load_signature(public.ipk, raw)
        require(runtime.ibs.verify(public.ipk, ALICE.encode(), encode_message(BOB.encode(), old), restored) is True,
                'old signature must be honest')
        require(runtime.ibs.verify(public.ipk, ALICE.encode(), encode_message(BOB.encode(), altered), restored) is False,
                'old signature must reject altered message')
        payload = DOMAIN_SIGNATURE + encode_bytes(raw) + encode_bytes(altered)
        inner = Ciphertext(runtime.hibe.encrypt(public.hpk, BOB.encode(), ALICE.encode(), payload))
        forged = authenticate_inner(public, inner.to_bytes(), ots)
        require(forged.ots_key.verify(forged.signed_body(), forged.signature) is True, 'outer OTS must be valid')
    observations = []
    verify = runtime.ibs.verify

    def observed(*args, **kwargs):
        value = verify(*args, **kwargs)
        observations.append(value)
        return value

    runtime.ibs.verify = observed
    with measured_phase('complete-protocol-inner-rejection', rows):
        rejected = runtime.proto.decrypt(public, receiver, ALICE.encode(), forged) is BOTTOM
    require(rejected and observations == [False], 'rejection must actually reach IBS verification')
    require(before == snapshot(state), 'inner probe changed original CLI state')
    return dict(outer_ots_valid=True, honest_old_signature_valid=True, altered_message_signature_valid=False,
                complete_protocol_rejected=True, ibs_verification_results=observations, original_state_unchanged=True,
                ciphertext_bytes=len(forged.to_bytes()))


def worker(request):
    from experiments.research.runtime_metrics import measured_phase
    from ibme.core.randomness import SecureRandom
    counts = dict(bytes=0, reads=0)
    calls = {}
    original = SecureRandom.read

    def counted(self, n):
        counts['reads'] += 1
        counts['bytes'] += n
        require(not request['zero'], 'forbidden new entropy')
        return original(self, n)

    SecureRandom.read = counted
    from ibme.hibe.latte.engine import Native
    from ibme.hibe.lai.backend import LaiHIBE
    from ibme.ibs.certified.mldsa import MLDSA
    from ibme.protocol.baseline import BaselineIBME

    def native_guard(label, method):
        def guarded(self, operation, *args, **kwargs):
            key = label + ':' + operation
            calls[key] = calls.get(key, 0) + 1
            allowed = ('meta', 'decrypt') if label == 'latte' else ('meta', 'public', 'verify', 'signature')
            require(not request['zero'] or operation in allowed, 'forbidden native generation')
            return method(self, operation, *args, **kwargs)
        return guarded

    Native.call = native_guard('latte', Native.call)
    MLDSA._run = native_guard('mldsa', MLDSA._run)

    def method_guard(label, method):
        def guarded(self, *args, **kwargs):
            calls[label] = calls.get(label, 0) + 1
            require(not request['zero'], 'forbidden generation or uncached derive')
            return method(self, *args, **kwargs)
        return guarded

    LaiHIBE.derive = method_guard('lai:derive', LaiHIBE.derive)
    for name in ('setup', 'skgen', 'rkgen', 'encrypt'):
        setattr(BaselineIBME, name, method_guard('protocol:' + name, getattr(BaselineIBME, name)))
    from ibme.cli import main as cli_main
    out, err, phases = io.StringIO(), io.StringIO(), []
    exception, extra = None, {}
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            if request['action'] == 'inner':
                extra = inner_signature_probe(Path(request['state']), phases)
                code = 0
            else:
                with measured_phase('cli-main', phases):
                    code = cli_main(request['args'])
        except BaseException as exc:
            code, exception = 99, type(exc).__name__
    return dict(code=code, exception=exception, entropy_reads=counts['reads'], entropy_bytes=counts['bytes'],
                native_calls=calls, phases=phases, stdout=out.getvalue(), stderr=err.getvalue(),
                providers=providers(), **extra)


def command(directory, name, args, *, expected=0, zero=False, timeout=1200, action='cli'):
    request_path = directory / (name + '.request.json')
    write_new(request_path, dict(args=list(map(str, args)), zero=zero, action=action, state=str(directory / 'state')))
    invocation = [sys.executable, '-m', 'experiments.research.report_experiment_probe', '--worker', str(request_path)]
    started = time.perf_counter()
    process = subprocess.Popen(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        write_new(directory / (name + '.timeout.json'), dict(status='failed', timeout_seconds=timeout, no_outer_retry=True))
        raise
    write_new(directory / (name + '.private-log'), stdout + stderr)
    require(process.returncode == 0, name + ': child interpreter failed')
    row = json.loads(stdout)
    row.pop('stdout')
    row.pop('stderr')
    row.update(name=name, expected_code=expected, zero_entropy_required=zero,
               fresh_process_wall_seconds=time.perf_counter() - started)
    validate_command(row, expected=expected, zero=zero)
    print(name + ' passed', flush=True)
    return row


def generate(directory, suite, *, source_commit, prefix, lengths=None, identity_negatives=True,
             with_inner_check=False, timeout=1200):
    from ibme.assembly import SuiteConfig, validate_suite
    from experiments.research.runtime_metrics import environment
    config = SuiteConfig.from_dict(suite)
    report = validate_suite(config)
    require(report.ok, 'public preflight failed: ' + repr(report.errors))
    capacity = report.capacity['max_application_bytes']
    lengths = [0, 32, 1024, capacity] if lengths is None else lengths
    validate_lengths(lengths, capacity)
    directory.mkdir(parents=True, exist_ok=False)
    os.chmod(directory, 0o700)
    write_new(directory / 'generation.pending', b'one attempt; preserve on failure\n')
    write_new(directory / 'suite.json', suite)
    state, records, observations = directory / 'state', [], []
    source_files = {}
    stage = 'setup'

    def run(name, args, *, expected=0, zero=False, action='cli'):
        nonlocal stage
        stage = name
        row = command(directory, name, args, expected=expected, zero=zero, timeout=timeout, action=action)
        merge_providers(source_files, row.pop('providers'), prefix=prefix)
        records.append(row)
        return row

    try:
        run('setup', setup_arguments(suite, state))
        meta = json.loads((state / 'state.json').read_bytes())
        require(meta['suite'] == suite and meta['suite_digest'] == config.digest, 'CLI selected a different Suite')
        run('sender', ['issue-sender-key', ALICE, '--state', state])
        run('receiver', ['issue-receiver-key', BOB, '--state', state])
        if identity_negatives:
            run('other-receiver', ['issue-receiver-key', CAROL, '--state', state])
        before = snapshot(state)
        run('same-sender', ['issue-sender-key', ALICE, '--state', state])
        run('same-receiver', ['issue-receiver-key', BOB, '--state', state])
        require(before == snapshot(state), 'same-address issuance changed state')
        for length in lengths:
            message = (bytes(range(256)) * ((length + 255) // 256))[:length]
            message_path, cipher_path = directory / f'message-{length}.bin', directory / f'cipher-{length}.bin'
            output = directory / f'recovered-{length}.bin'
            write_new(message_path, message)
            run(f'encrypt-{length}', ['encrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
                                     '--in', message_path, '--out', cipher_path])
            run(f'decrypt-{length}', ['decrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
                                     '--in', cipher_path, '--out', output])
            require(output.read_bytes() == message, 'message recovery mismatch')
            observations.append(dict(message_bytes=length, message_sha256=hashlib.sha256(message).hexdigest(),
                                     ciphertext_bytes=cipher_path.stat().st_size, recovered=True))
        before = snapshot(state)
        too_long, rejected_output = directory / 'over-capacity.bin', directory / 'over-capacity.ct'
        write_new(too_long, bytes(capacity + 1))
        rejected = run('capacity-plus-one', ['encrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
                                            '--in', too_long, '--out', rejected_output], expected=2, zero=True)
        require(not rejected_output.exists() and before == snapshot(state), 'capacity rejection changed state/output')
        rejected_output = directory / 'over-identity.ct'
        run('identity-plus-one', ['encrypt', '--state', state, '--sender', ALICE, '--receiver', BOB + '!',
                                 '--in', message_path, '--out', rejected_output], expected=2, zero=True)
        require(not rejected_output.exists() and before == snapshot(state), 'identity rejection changed state/output')
        if identity_negatives:
            for name, sender, receiver in [('wrong-sender', EVE, BOB), ('wrong-receiver', ALICE, CAROL),
                                           ('both-wrong', EVE, CAROL)]:
                output = directory / (name + '.output')
                run(name, ['decrypt', '--state', state, '--sender', sender, '--receiver', receiver,
                           '--in', cipher_path, '--out', output], expected=1)
                require(not output.exists(), 'wrong identity produced output')
        wire = cipher_path.read_bytes()
        for name, raw in [('truncated', wire[:-1]), ('appended', wire + b'!'),
                          ('duplicate', wire + wire), ('changed', wire[:-1] + bytes([wire[-1] ^ 1]))]:
            path, output = directory / (name + '.input'), directory / (name + '.output')
            write_new(path, raw)
            run(name, ['decrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
                       '--in', path, '--out', output], expected=1, zero=True)
            require(not output.exists(), 'malformed ciphertext produced output')
        before = snapshot(state)
        output = directory / 'fresh-restored.bin'
        zero = suite['hibe'] == 'latte'
        restored = run('fresh-process-restore', ['decrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
                                               '--in', cipher_path, '--out', output], zero=zero)
        require(output.read_bytes() == message and before == snapshot(state), 'restore changed state or plaintext')
        if not zero:
            require(restored['native_calls'].get('lai:derive') == 1, 'uncached Lai restore must execute Derive')
        if with_inner_check:
            run('valid-outer-invalid-inner', [], action='inner')
        require(not list(state.glob('*.pending')), 'CLI pending operation remains')
        result = dict(schema='REPORT-EXACT-SUITE-CLI/1', status='passed', source_commit=source_commit,
                      suite=suite, suite_digest=config.digest, capacity=report.capacity, environment=environment(),
                      identity_bytes=64, observations=observations, commands=records, providers=source_files,
                      identity_negatives_executed=identity_negatives, inner_signature_check_executed=with_inner_check,
                      state_file_bytes={p.name: p.stat().st_size for p in state.iterdir() if p.is_file() and p.suffix == '.bin'},
                      restored_state_unchanged=True, restored_decrypt_zero_entropy=zero,
                      root_count=1, no_outer_retry=True, security_claim='none', backend_admitted=False,
                      parameters_are_formal=False, uses_ROM=True,
                      limitations=['Single root functional supplement, not a repeated benchmark.',
                                   'CLI main timings and process wall timings are separate.',
                                   'RSS samples may miss spikes; kernel ru_maxrss is lifetime, not phase-isolated.'])
        write_new(directory / 'public-receipt.json', result)
        os.replace(directory / 'generation.pending', directory / 'generation.done')
        return result
    except BaseException as exc:
        write_new(directory / 'failure.json', dict(status='failed', stage=stage, exception_type=type(exc).__name__,
                  private_outputs_preserved=True, no_outer_retry=True, completed_commands=records))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--private-directory', type=Path)
    parser.add_argument('--suite', type=Path)
    parser.add_argument('--source-commit')
    parser.add_argument('--installed-prefix', type=Path)
    parser.add_argument('--lengths', type=int, nargs='+')
    parser.add_argument('--skip-identity-negatives', action='store_true')
    parser.add_argument('--with-inner-check', action='store_true')
    parser.add_argument('--timeout', type=int, default=1200)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(json.loads(args.worker.read_bytes())), sort_keys=True))
        return
    require(all((args.private_directory, args.suite, args.source_commit, args.installed_prefix)), 'provide experiment paths/source')
    require(1 <= args.timeout <= 1800, 'bounded command timeout required')
    result = generate(args.private_directory.resolve(), json.loads(args.suite.read_bytes()),
                      source_commit=args.source_commit, prefix=args.installed_prefix.resolve(), lengths=args.lengths,
                      identity_negatives=not args.skip_identity_negatives, with_inner_check=args.with_inner_check,
                      timeout=args.timeout)
    print(json.dumps(dict(status=result['status'], commands=len(result['commands']), suite_digest=result['suite_digest'])))


if __name__ == '__main__':
    main()
