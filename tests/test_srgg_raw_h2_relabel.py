"""Independent bit/slice checks of the bounded reversible H2 reference."""
import pytest

from experiments.research.candidates.srgg import raw_h2_relabel as subject


def independent(prefix, degree):
    bits = [(value >> i) & 1 for value in prefix for i in range(8)]
    half = degree//2
    out = list(bits)
    for i in range(half):
        out[i] = bits[i]^bits[half+i]
    return bytes(sum(out[8*j+k] << k for k in range(8))
                 for j in range(len(prefix)))


@pytest.mark.parametrize("degree", [2, 4, 8])
def test_full_prefix_cnot_conjugation_exhaustive_basis(degree):
    # All oracle words and all (including nonzero) target register values.
    for word in range(256):
        reply = bytes([word])
        expected = independent(reply, degree)
        assert subject.relabel_prefix(reply, degree) == expected
        assert subject.relabel_prefix(expected, degree) == reply
        oracle = lambda _x, _o, _s: reply
        for target in range(256):
            assert subject.conjugated_full_prefix(oracle, degree=degree,
                point=b"point", target=bytes([target])) == bytes([target^expected[0]])


@pytest.mark.parametrize("degree", [2, 4, 8, 16, 512])
def test_all_boundary_slices_round_trip_and_scratch(degree):
    width = (degree+7)//8
    # Two independent, completely fixed finite raw streams; no RNG or SHAKE.
    tables = {b"x": bytes((j*17+3) & 255 for j in range(subject.MAX_BYTES)),
              b"y": bytes((j*29+8) & 255 for j in range(subject.MAX_BYTES))}
    for point, stream in tables.items():
        renamed = independent(stream[:width], degree)+stream[width:]
        cases = {(0, 0), (0, 1), (0, width), (width, 0), (width, 1),
                 (max(0, width-1), 3), (0, subject.MAX_BYTES),
                 (subject.MAX_BYTES, 0), (subject.MAX_BYTES-1, 1)}
        for offset, size in cases:
            calls = []
            def oracle(x, o, s):
                calls.append((x, o, s))
                return tables[x][o:o+s]
            target = bytes((i*7+99) & 255 for i in range(size))
            expected = bytes(a^b for a, b in zip(target, renamed[offset:offset+size]))
            result = subject.relabeled_basis_query(oracle, degree=degree,
                point=point, offset=offset, size=size, target=target)
            assert result.output == expected
            assert result.scratch_is_zero
            assert (result.prefix_query_count, result.suffix_query_count) == (2, 1)
            assert len(calls) == 3
            assert calls[0] == calls[-1] == (point, 0, width)
            # Feed the renamed function through the same involution.
            inverse = subject.relabeled_basis_query(
                lambda _x, o, s: renamed[o:o+s], degree=degree,
                point=point, offset=offset, size=size, target=target)
            assert inverse.output == bytes(a^b for a, b in
                zip(target, stream[offset:offset+size]))


@pytest.mark.parametrize("degree", [2, 4, 8, 16, 512])
def test_query_schedule_is_independent_of_all_reply_bits(degree):
    logs = []
    for bit in (0, 255):
        log = []
        def oracle(x, o, s):
            log.append((x, o, s))
            return bytes([bit])*s
        subject.relabeled_basis_query(oracle, degree=degree, point=b"raw",
            offset=1, size=3, target=b"abc")
        logs.append(log)
    assert logs[0] == logs[1]


@pytest.mark.parametrize("change", ["degree", "boolean", "point", "offset", "size", "sum", "target"])
def test_invalid_input_uses_no_oracle_queries(change):
    args = dict(degree=8, point=b"point", offset=0, size=1, target=b"x")
    args.update({"degree": {"degree": 3}, "boolean": {"degree": True},
        "point": {"point": bytearray(b"x")}, "offset": {"offset": -1},
        "size": {"size": True}, "sum": {"offset": subject.MAX_BYTES},
        "target": {"target": b""}}[change])
    def forbidden(*_args):
        pytest.fail("invalid metadata reached oracle")
    with pytest.raises(ValueError):
        subject.relabeled_basis_query(forbidden, **args)


def test_changing_oracle_and_truncated_reply_are_rejected():
    count = 0
    def changing(_x, _o, size):
        nonlocal count
        count += 1
        return bytes([count])*size
    with pytest.raises(ValueError, match="compute and uncompute"):
        subject.relabeled_basis_query(changing, degree=8, point=b"x", offset=0,
                                     size=1, target=b"\x00")
    with pytest.raises(ValueError, match="invalid bytes"):
        subject.relabeled_basis_query(lambda *_args: b"", degree=8, point=b"x",
                                     offset=0, size=1, target=b"\x00")
