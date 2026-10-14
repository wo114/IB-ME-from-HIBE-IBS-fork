"""Cheap snapshot shape/size checks before invoking the research matrix engine."""
from dataclasses import asdict
from math import isqrt

from ibme.core.errors import SerializationError
from .codec import canonical, parse_json


def hex_bytes(value, minimum, maximum):
    if type(value) is not str or not 2*minimum <= len(value) <= 2*maximum or len(value) % 2:
        raise SerializationError("invalid Foo-Li snapshot byte field")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise SerializationError("invalid Foo-Li snapshot hex") from exc
    if result.hex() != value:
        raise SerializationError("noncanonical Foo-Li snapshot hex")
    return result


def matrix_shape(rows, nrows, ncols, *, low, high, quality=None):
    if type(rows) is not list or len(rows) != nrows:
        raise SerializationError("Foo-Li snapshot matrix row count mismatch")
    squared = 0
    for row in rows:
        if type(row) is not list or len(row) != ncols:
            raise SerializationError("Foo-Li snapshot matrix column count mismatch")
        for value in row:
            if type(value) is not int or not low <= value <= high:
                raise SerializationError("Foo-Li snapshot matrix entry outside range")
            squared += value*value
    if quality is not None and squared > quality:
        raise SerializationError("Foo-Li snapshot trapdoor exceeds declared quality")


def validate_snapshot(pk, secret, encoded_states):
    """Return the checked issuance ledger. No Sage matrices or sampling here."""
    from experiments.research.foo_li_runtime_reference import VERSION
    p = pk.params
    record = parse_json(secret)
    if type(record) is not dict or set(record) != {"version", "config", "epoch", "base", "R0", "k1", "k2", "users", "failures"}:
        raise SerializationError("invalid Foo-Li research snapshot fields")
    if (record["version"] != VERSION
            or canonical(record["config"]) != canonical(asdict(p.research_config()))
            or hex_bytes(record["epoch"], 1, 256) != pk.epoch):
        raise SerializationError("Foo-Li research snapshot public configuration mismatch")
    hex_bytes(record["k1"], 32, 32)
    hex_bytes(record["k2"], 32, 32)
    matrix_shape(record["base"], p.n, p.m_bar, low=0, high=p.q-1)
    root_bound = isqrt(p.master_quality)
    matrix_shape(record["R0"], p.m_bar, p.w, low=-root_bound, high=root_bound, quality=p.master_quality)
    users, failures = record["users"], record["failures"]
    if type(users) is not list or type(failures) is not list or len(users)+len(failures) > p.max_users:
        raise SerializationError("invalid Foo-Li snapshot identity counts")
    issued, failed, previous = set(), set(), b""
    for item in users:
        if type(item) is not dict or set(item) != {"id", "bit", "T", "seed"}:
            raise SerializationError("invalid Foo-Li user fields")
        identity = hex_bytes(item["id"], 1, p.identity_max_bytes)
        if identity <= previous or type(item["bit"]) is not int or item["bit"] not in (0, 1):
            raise SerializationError("invalid Foo-Li user ordering/branch")
        previous = identity
        issued.add(identity)
        hex_bytes(item["seed"], 32, 32)
        bound = isqrt(p.user_quality)
        matrix_shape(item["T"], p.m, p.w, low=-bound, high=bound, quality=p.user_quality)
    previous = b""
    for item in failures:
        if type(item) is not list or len(item) != 2:
            raise SerializationError("invalid Foo-Li failure fields")
        identity = hex_bytes(item[0], 1, p.identity_max_bytes)
        if (identity <= previous or identity in issued
                or item[1] not in ("identity_hash_abort", "delegation_sampling_abort", "user_quality_rejected")):
            raise SerializationError("invalid Foo-Li failure record")
        previous = identity
        failed.add(identity)
    states = parse_json(encoded_states)
    if type(states) is not list or len(states) > p.max_users:
        raise SerializationError("Foo-Li issuance ledger exceeds capacity")
    checked, previous = {}, b""
    for item in states:
        if type(item) is not list or len(item) != 2:
            raise SerializationError("invalid Foo-Li issuance record")
        identity = hex_bytes(item[0], 1, p.identity_max_bytes)
        if identity <= previous or item[1] not in ("pending", "failed", "issued"):
            raise SerializationError("invalid Foo-Li issuance ordering/status")
        previous = identity
        checked[identity] = item[1]
    if {i for i,s in checked.items() if s == "issued"} != issued or any(checked.get(i) != "failed" for i in failed):
        raise SerializationError("Foo-Li issuance ledger/key/tombstone mismatch")
    return checked
