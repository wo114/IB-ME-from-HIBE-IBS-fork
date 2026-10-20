"""Fresh-process SRGG paper CLI acceptance using the existing CLI probe.

Private state/logs stay in an exclusive output directory. Only the existing
allowlisted command receipt and public suite/provider metadata are exported.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time

from .c_framework_cli_probe import ALICE, BOB, CAROL, EVE, command, replay, snapshot


def require(condition, message):
    if not condition:
        raise ValueError(message)


def setup_arguments(state, suite_file=None):
    """Bind the probe's CLI selection to a complete, versioned public Suite.

    The historical no-file invocation retains its 64 KiB defaults. An explicit
    Suite is limited to this LATTE/SRGG PARAM-I compact probe, and must round-trip
    through the current registry before any private output or root is created.
    """
    from ibme.assembly import SuiteConfig, make_suite

    args = ['setup', '--state', state, '--hibe', 'latte', '--hibe-params', 'seed32',
            '--ibs', 'srgg2025-paper', '--ibs-params', 'PARAM-I', '--transport', 'hybrid',
            '--signature-format', 'compact']
    if suite_file is None:
        return args, None
    expected = SuiteConfig.from_json(Path(suite_file).read_bytes())
    raw = expected.to_dict()
    require(raw['hibe'] == 'latte' and raw['ibs'] == 'srgg2025-paper'
            and raw['signature_format'] == 'compact' and raw['transport'] == 'hybrid'
            and raw['protocol'] == 'byteauth-v1' and raw['allow_mock'] is False,
            'Suite is outside the LATTE/SRGG compact probe scope')
    current = make_suite(hibe='latte', hibe_params='seed32', ibs='srgg2025-paper',
                         ibs_params='PARAM-I', transport='hybrid', signature_format='compact',
                         hybrid_limits=raw['hybrid_limits'])
    require(current.to_dict() == raw, 'Suite parameters, versions or claims differ from probe scope')
    args += ['--hybrid-limits', json.dumps(raw['hybrid_limits'], sort_keys=True)]
    return args, expected


def generate(directory, source_commit, *, suite_file=None):
    setup_args, expected_suite = setup_arguments(directory / 'state', suite_file)
    directory.mkdir(parents=True, exist_ok=False)
    state = directory / 'state'
    records = []
    stage = 'setup'
    started = time.perf_counter()
    try:
        message = hashlib.sha256(b'SRGG paper public CLI acceptance').digest()
        (directory / 'message.bin').write_bytes(message)

        def run(name, args, expected=0):
            nonlocal stage
            stage = name
            row = command(directory, name, args, expected=expected)
            records.append(row)

        run('setup', setup_args)
        stage = 'frozen-suite-binding'
        meta = json.loads((state/'state.json').read_bytes())
        if expected_suite is not None:
            require(meta['suite'] == expected_suite.to_dict()
                    and meta['suite_digest'] == expected_suite.digest,
                    'installed CLI did not produce the requested frozen Suite')
        run('sender', ['issue-sender-key', ALICE, '--state', state])
        for name, identity in [('receiver', BOB), ('other-receiver', CAROL)]:
            run(name, ['issue-receiver-key', identity, '--state', state])
        before = snapshot(state)
        run('same-sender', ['issue-sender-key', ALICE, '--state', state])
        run('same-receiver', ['issue-receiver-key', BOB, '--state', state])
        require(before == snapshot(state), 'repeated issuance changed the original state')
        run('encrypt', ['encrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
            '--in', directory/'message.bin', '--out', directory/'cipher.bin'])
        run('decrypt', ['decrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
            '--in', directory/'cipher.bin', '--out', directory/'recovered.bin'])
        require((directory/'recovered.bin').read_bytes() == message, 'honest plaintext mismatch')
        for name, sender, receiver in [('wrong-sender', EVE, BOB), ('wrong-receiver', ALICE, CAROL),
                                       ('both-wrong', EVE, CAROL)]:
            output = directory/(name+'.bin')
            run(name, ['decrypt', '--state', state, '--sender', sender, '--receiver', receiver,
                '--in', directory/'cipher.bin', '--out', output], expected=1)
            require(not output.exists(), 'wrong identity produced output')
        wire = (directory/'cipher.bin').read_bytes()
        for name, raw in [('truncated', wire[:-1]), ('appended', wire+b'!'),
                          ('duplicate', wire+wire), ('changed', wire[:-1]+bytes([wire[-1]^1]))]:
            path = directory/(name+'.input')
            path.write_bytes(raw)
            output = directory/(name+'.output')
            run(name, ['decrypt', '--state', state, '--sender', ALICE, '--receiver', BOB,
                '--in', path, '--out', output], expected=1)
            require(not output.exists(), 'invalid ciphertext produced output')
        stage = 'zero-entropy-restore'
        restore_before = snapshot(state)
        restored = replay(directory)
        require(restore_before == snapshot(state), 'restore changed original state')
        require((directory/'restored.bin').read_bytes() == message, 'restored plaintext mismatch')
        require(not list(state.glob('*.pending')), 'restore left pending state')
        require(restored['command']['entropy_reads'] == restored['command']['entropy_bytes'] == 0,
                'restore consumed project entropy')
        providers = {}
        for row in records+[restored['command']]:
            for name, value in row.pop('providers').items():
                if name in providers:
                    require(providers[name] == value, 'provider changed during CLI run')
                providers[name] = value
        meta = json.loads((state/'state.json').read_bytes())
        receipt = dict(schema='SRGG-PAPER-CLI/1', status='passed', source_commit=source_commit,
            parameters=meta['suite'], state_version=meta['version'], identity_bytes=64, message_bytes=32,
            commands=records, restore=restored, providers=providers, repetitions=1,
            ciphertext_bytes=len(wire), public_key_bytes=(state/'mpk.bin').stat().st_size,
            total_seconds=time.perf_counter()-started,
            randomness='system CSPRNG; no fixed seed or outer retry; new process per CLI command',
            security_claim='none', backend_admitted=False, parameters_are_formal=False)
        if expected_suite is not None:
            receipt.update(requested_suite_digest=expected_suite.digest,
                           installed_suite_digest=meta['suite_digest'], frozen_suite_matched=True)
        (directory/'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n', encoding='utf-8')
        return dict(status='passed', commands=len(records), zero_entropy_restore=True)
    except BaseException as exc:
        (directory/'failure.json').write_text(json.dumps(dict(status='failed', stage=stage,
            exception=type(exc).__name__, private_outputs_preserved=True, no_outer_retry=True), indent=2)+'\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-directory', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--suite-file', type=Path,
                        help='complete frozen LATTE/SRGG PARAM-I compact Suite; no default-budget substitution')
    args = parser.parse_args()
    print(json.dumps(generate(args.private_directory.resolve(), args.source_commit,
                              suite_file=args.suite_file)))


if __name__ == '__main__':
    main()
