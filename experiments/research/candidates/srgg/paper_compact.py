"""Optional lossless binary transport for original Table 4 SRGG objects.

The existing JSON object bytes, hash domains, context, sampler, parameters,
norm gates and default issuer storage remain unchanged. Loading returns those
same object classes. This is neither encryption nor a constant-time codec.
"""
from __future__ import annotations

from ibme.core.errors import EncodingError, SerializationError

from .paper_algebra import PaperRing, public_matrix
from .paper_compact_bits import Reader, Writer, pack, unpack, zigzag, unzigzag
from .paper_objects import MasterSecret, PublicKey, Signature, SigningKey, MAX_USERS, MAX_WIRE
from .paper_parameters import PaperParams


MAGIC = b"IBME/SRGG-COMPACT\x00"
VERSION = 1
SOURCE_SHA256 = "258583c5b90255afe91343a282cb62840198b1192b6462dfc9597a24f8c01152"
PROFILES = ("PARAM-I", "PARAM-II", "PARAM-III")
INTERPRETATIONS = ("table-standard-deviation", "literal-density-width")
KINDS = {"public": 1, "key": 2, "master": 3, "signature": 4}
STATUSES = ("pending", "failed", "issued")
HEADER_BYTES = len(MAGIC)+4+32


def _parameters(params):
    if type(params) is not PaperParams:
        raise SerializationError("published PaperParams required for compact codec")
    record = {"profile_name": params.profile_name, "interpretation": params.interpretation,
        "source_sha256": SOURCE_SHA256, "perturbation_noise_factor": 1,
        "hnf_representative": "centered-mod-Q", "gadget_remainder_representative": "centered-mod-p",
        "pi_precision_bits": 512, "r_published_approximation": "1.16"}
    if (PaperParams.from_record(record) != params or params.record() != record
            or params.degree != 512 or params.digits != 2 or params.modulus != 15744063
            or params.rank != PROFILES.index(params.profile_name)+2):
        raise SerializationError("compact parameter convention mismatch")
    return params


def _header(writer, kind, params):
    _parameters(params)
    writer.add(MAGIC)
    writer.add(bytes((VERSION, KINDS[kind], PROFILES.index(params.profile_name)+1,
                      INTERPRETATIONS.index(params.interpretation)+1)))
    writer.add(bytes.fromhex(SOURCE_SHA256))


def _read_header(reader, kind):
    if reader.take(len(MAGIC)) != MAGIC:
        raise SerializationError("compact magic mismatch")
    version, wire_kind, profile, interpretation = reader.take(4)
    if (version != VERSION or wire_kind != KINDS[kind]
            or not 1 <= profile <= len(PROFILES)
            or not 1 <= interpretation <= len(INTERPRETATIONS)
            or reader.take(32) != bytes.fromhex(SOURCE_SHA256)):
        raise SerializationError("compact version/kind/source/profile mismatch")
    return _parameters(PaperParams(PROFILES[profile-1], INTERPRETATIONS[interpretation-1]))


def _flatten(vector):
    return (value for poly in vector for value in poly)


def _shape(values, rows, columns=None, degree=512):
    """Build only dimensions already fixed by the validated profile."""
    if columns is None:
        return tuple(tuple(values[i*degree:(i+1)*degree]) for i in range(rows))
    return tuple(_shape(values[i*columns*degree:(i+1)*columns*degree], columns,
                        degree=degree) for i in range(rows))


def _identity(writer, identity):
    if type(identity) is not bytes or not 1 <= len(identity) <= 4096:
        raise SerializationError("bounded compact identity required")
    writer.integer(len(identity), 2)
    writer.add(identity)


def _read_identity(reader):
    size = reader.integer(2)
    if not 1 <= size <= 4096:
        raise SerializationError("compact identity length out of range")
    return reader.take(size)


def _vector(writer, value):
    width = max((zigzag(x).bit_length() for x in _flatten(value)), default=0)
    writer.integer(width, 2)
    writer.add(pack((zigzag(x) for x in _flatten(value)), width))


def _read_vector(reader, count, degree):
    width = reader.integer(2)
    if width > 257:
        raise SerializationError("compact signed vector width out of range")
    # Reader.take checks the entire field before unpack allocates any values.
    values = unpack(reader.take((count*degree*width+7)//8), count*degree, width)
    if max((x.bit_length() for x in values), default=0) != width:
        raise SerializationError("nonminimal compact signed vector width")
    return _shape(tuple(unzigzag(x) for x in values), count, degree=degree)


def _public_size(params):
    return HEADER_BYTES+32+3*params.rank**2*params.digits*params.degree


def _public(writer, public):
    if type(public) is not PublicKey:
        raise SerializationError("paper PublicKey required for compact codec")
    checked = PublicKey(public.params, public.seed, public.a_hat, public.b)
    _header(writer, "public", checked.params)
    writer.add(checked.seed)
    writer.add(pack((x for row in checked.b for poly in row for x in poly), 24))


def _read_public(reader):
    params = _read_header(reader, "public")
    seed = reader.take(32)
    count = params.rank**2*params.digits*params.degree
    values = unpack(reader.take(3*count), count, 24)
    if any(x >= params.modulus for x in values):
        raise SerializationError("noncanonical compact public residue")
    b = _shape(values, params.rank, params.rank*params.digits, params.degree)
    return PublicKey(params, seed, public_matrix(params, seed), b)


def _bound_public(public, params, expected_public=None):
    if public.params != params:
        raise SerializationError("compact outer/embedded parameter mismatch")
    if expected_public is not None and (type(expected_public) is not PublicKey
            or public.to_bytes() != expected_public.to_bytes()):
        raise SerializationError("compact expected public mismatch")


def _load(data, kind, parse, dump):
    try:
        reader = Reader(data, MAX_WIRE)
        value = parse(reader)
        reader.finish()
        if dump(value) != data:
            raise SerializationError("noncanonical compact object")
        return value
    except (ValueError, TypeError, KeyError, OverflowError, EncodingError):
        raise SerializationError("invalid compact SRGG "+kind) from None


def dump_public(public):
    writer = Writer(MAX_WIRE)
    _public(writer, public)
    return writer.finish()


def load_public(data):
    return _load(data, "public", _read_public, dump_public)


def dump_key(key):
    if type(key) is not SigningKey:
        raise SerializationError("paper SigningKey required for compact codec")
    checked = SigningKey(key.public_key, key.identity, key.tail)
    writer = Writer(MAX_WIRE)
    _header(writer, "key", checked.public_key.params)
    _public(writer, checked.public_key)
    _identity(writer, checked.identity)
    _vector(writer, checked.tail)
    return writer.finish()


def load_key(data, expected_public=None):
    def parse(reader):
        params = _read_header(reader, "key")
        public = _read_public(reader)
        _bound_public(public, params, expected_public)
        identity = _read_identity(reader)
        tail = _read_vector(reader, (1+params.digits)*params.rank, params.degree)
        return SigningKey(public, identity, tail)
    return _load(data, "key", parse, dump_key)


def dump_master(master):
    if type(master) is not MasterSecret:
        raise SerializationError("paper MasterSecret required for compact codec")
    checked = MasterSecret(master.public_key, master.witness, master.states)
    writer = Writer(MAX_WIRE)
    _header(writer, "master", checked.public_key.params)
    _public(writer, checked.public_key)
    writer.add(pack((x+1 for row in checked.witness for poly in row for x in poly), 2))
    entries = checked._entries()
    writer.integer(len(entries), 1)
    for identity_hex, status, tail in entries:
        _identity(writer, bytes.fromhex(identity_hex))
        writer.integer(STATUSES.index(status), 1)
        if status == "issued":
            _vector(writer, tail)
    return writer.finish()


def load_master(data, expected_public=None):
    def parse(reader):
        params = _read_header(reader, "master")
        public = _read_public(reader)
        _bound_public(public, params, expected_public)
        count = 2*params.rank**2*params.digits*params.degree
        values = unpack(reader.take((2*count+7)//8), count, 2)
        if 3 in values:
            raise SerializationError("invalid compact CBD1 code")
        witness = _shape(tuple(x-1 for x in values), 2*params.rank,
                         params.rank*params.digits, params.degree)
        count = reader.integer(1)
        if count > MAX_USERS:
            raise SerializationError("compact issuance cache exceeds capacity")
        states, previous = {}, None
        for _ in range(count):
            identity = _read_identity(reader)
            status = reader.integer(1)
            if status >= len(STATUSES) or previous is not None and identity <= previous:
                raise SerializationError("compact status/identity order mismatch")
            previous = identity
            tail = (_read_vector(reader, (1+params.digits)*params.rank, params.degree)
                    if status == 2 else None)
            states[identity] = (STATUSES[status], SigningKey(public, identity, tail)
                                if status == 2 else None)
        return MasterSecret(public, witness, states)
    return _load(data, "master", parse, dump_master)


def _signature(public, signature):
    if type(public) is not PublicKey or type(signature) is not Signature:
        raise SerializationError("paper public/signature objects required for compact codec")
    checked = Signature(signature.context, signature.response, signature.challenge)
    p = public.params
    PaperRing(p).vector(checked.response, p.columns+1)
    if len(checked.challenge) != p.degree or checked.context != public.context:
        raise SerializationError("compact signature public/dimension mismatch")
    return checked


def dump_signature(public, signature):
    checked = _signature(public, signature)
    writer = Writer(MAX_WIRE)
    _header(writer, "signature", public.params)
    writer.add(checked.context)
    _vector(writer, checked.response)
    writer.add(pack(checked.challenge, 1))
    return writer.finish()


def load_signature(public, data):
    def parse(reader):
        params = _read_header(reader, "signature")
        if type(public) is not PublicKey or public.params != params:
            raise SerializationError("compact signature profile mismatch")
        context = reader.take(32)
        response = _read_vector(reader, params.columns+1, params.degree)
        challenge = unpack(reader.take((params.degree+7)//8), params.degree, 1)
        return _signature(public, Signature(context, response, challenge))
    return _load(data, "signature", parse,
                 lambda signature: dump_signature(public, signature))
