"""Independent HIBE/IBS selection, entropy-free compatibility and assembly.

This layer reuses the existing protocol and primitive algorithms. Every built-in
suite retains security_claim=none and backend_admitted=false. A compatible
configuration is not a claim that a full combination has been tested or proved.
"""
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json

from ibme.core.encoding import encode_message
from ibme.core.errors import IBMEError, InvalidParameterError, SerializationError
from ibme.core.types import validate_bytes, validate_identity
from ibme.lattice.params import Params
from ibme.protocol.baseline import BaselineIBME, PublicKey, MasterSecret, SenderKey, ReceiverKey, DOMAIN_SIGNATURE, MAGIC_CIPHERTEXT, BOTTOM
from ibme.protocol.byteauth import ByteAuthenticatedIBME, ENVELOPE_OVERHEAD, MAX_INNER_BYTES
from .registry import BackendSpec, BackendRegistry, default_registry, environment_status

SUITE_VERSION = "IBME/SUITE/1"
STATE_POLICY = "single-writer-commit-before-publish-v1"
_MAX_CONFIG_BYTES = 32768


def _json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidParameterError("suite must contain finite JSON data") from exc


def _load_json(raw):
    if not isinstance(raw,(str,bytes)) or len(raw)>_MAX_CONFIG_BYTES:
        raise InvalidParameterError("suite JSON exceeds type/size budget")
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:
                raise InvalidParameterError(f"duplicate suite field: {key}")
            result[key]=value
        return result
    try:
        return json.loads(raw,object_pairs_hook=unique,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite number")))
    except (ValueError,UnicodeError,RecursionError) as exc:
        raise InvalidParameterError("malformed suite JSON") from exc


@dataclass(frozen=True)
class SuiteConfig:
    # Serialized immutable JSON prevents mutation of nested configuration maps.
    _json_data: str

    @classmethod
    def from_dict(cls, data):
        expected={"version","hibe","hibe_version","hibe_params","ibs","ibs_version","ibs_params",
                  "transport","protocol","signature_format","allow_mock","hybrid_limits","state_policy",
                  "security_claim","backend_admitted","parameters_are_formal"}
        if type(data) is not dict or set(data)!=expected:
            raise InvalidParameterError("suite requires exactly its versioned fields")
        if (data["version"]!=SUITE_VERSION or data["security_claim"]!="none"
                or data["backend_admitted"] is not False or data["parameters_are_formal"] is not False
                or type(data["allow_mock"]) is not bool):
            raise InvalidParameterError("unsupported suite version/type or security claim")
        for name in ("hibe","hibe_version","ibs","ibs_version","transport","protocol","signature_format","state_policy"):
            if type(data[name]) is not str or not data[name] or len(data[name])>128:
                raise InvalidParameterError(f"invalid suite field: {name}")
        for name in ("hibe_params","ibs_params","hybrid_limits"):
            if type(data[name]) is not dict:
                raise InvalidParameterError(f"suite {name} must be an object")
        raw=_json(data)
        if len(raw)>_MAX_CONFIG_BYTES:
            raise InvalidParameterError("suite JSON exceeds size budget")
        return cls(raw)

    @classmethod
    def from_json(cls, raw): return cls.from_dict(_load_json(raw))
    def to_json(self): return self._json_data
    def to_dict(self): return _load_json(self._json_data)
    @property
    def digest(self): return hashlib.sha256(self._json_data.encode("ascii")).hexdigest()
    @property
    def hibe(self): return self.to_dict()["hibe"]
    @property
    def ibs(self): return self.to_dict()["ibs"]
    @property
    def protocol(self): return self.to_dict()["protocol"]
    @property
    def signature_format(self): return self.to_dict()["signature_format"]
    @property
    def transport(self): return self.to_dict()["transport"]


def list_backends(*, registry=None):
    return (registry or default_registry()).list()


def make_suite(*, hibe="abb10", ibs="sis", hibe_params=None, ibs_params=None,
               transport="direct", protocol="byteauth-v1", signature_format="reference",
               allow_mock=False, hybrid_limits=None, state_policy=STATE_POLICY, registry=None):
    registry=registry or default_registry()
    hs,ins=registry.get("hibe",hibe),registry.get("ibs",ibs)
    def params(spec, selected):
        if not spec.available:
            if selected not in (None, {}):
                raise InvalidParameterError("unavailable backend has no parameter preset")
            return {}
        if selected is None:
            selected=(spec.default_preset(transport) if spec.default_preset is not None else
                      "hybrid-research" if spec.role=="hibe" and transport=="hybrid" else
                      "research" if spec.id.startswith("luo-") else "education")
        if isinstance(selected,spec.params_type):
            return asdict(selected)
        if type(selected) is str:
            if selected not in spec.presets:
                raise InvalidParameterError(f"{spec.id}: unknown parameter preset {selected!r}")
            return asdict(spec.presets[selected])
        return asdict(spec.parse_params(selected))
    limits=hybrid_limits if hybrid_limits is not None else ({
        "backend_id":hs.version,"identity_max_bytes":64,"max_payload_bytes":65536,"max_capsule_bytes":4*2**20
    } if transport=="hybrid" else {})
    return SuiteConfig.from_dict(dict(version=SUITE_VERSION,hibe=hibe,hibe_version=hs.version,
        hibe_params=params(hs,hibe_params),ibs=ibs,ibs_version=ins.version,ibs_params=params(ins,ibs_params),
        transport=transport,protocol=protocol,signature_format=signature_format,allow_mock=allow_mock,
        hybrid_limits=limits,state_policy=state_policy,security_claim="none",backend_admitted=False,parameters_are_formal=False))


@dataclass(frozen=True)
class CompatibilityReport:
    ok: bool
    errors: tuple
    capacity: dict
    metadata: dict
    def to_dict(self): return asdict(self)


def _resolve(config, registry):
    if not isinstance(config,SuiteConfig): raise InvalidParameterError("expected SuiteConfig")
    # Also validate callers constructing SuiteConfig directly, not via from_dict.
    data=SuiteConfig.from_json(config.to_json()).to_dict()
    hs,ins=registry.get("hibe",data["hibe"]),registry.get("ibs",data["ibs"])
    for spec in (hs,ins):
        if data[spec.role+"_version"]!=spec.version:
            raise InvalidParameterError(f"{spec.role}: backend version mismatch; no automatic migration")
        if not spec.available:
            raise InvalidParameterError(f"{spec.id}: unavailable: {spec.reason}")
    return data,hs,ins,hs.parse_params(data["hibe_params"]),ins.parse_params(data["ibs_params"])


def validate_suite(config, *, registry=None):
    """No Setup, key extraction, RNG reads, file writes or plugin imports from JSON."""
    registry=registry or default_registry()
    errors=[]; capacity={}
    metadata=dict(security_claim="none",backend_admitted=False,parameters_are_formal=False,
                  combination_tested=False,preflight_only=True)
    try:
        data,hs,ins,hp,ip=_resolve(config,registry)
        runtime_status={spec.role:environment_status(spec) for spec in (hs,ins)}
        metadata.update(runtime_available=all(row["runtime_available"] for row in runtime_status.values()),
                        runtime_dependencies=runtime_status,
                        persistent_identity_cache=hs.persistent_identity_cache or ins.persistent_identity_cache,
                        primitive_persistent_identity_cache={"hibe":hs.persistent_identity_cache,
                                                             "ibs":ins.persistent_identity_cache})
        for spec,params in ((hs,hp),(ins,ip)):
            if spec.validate_configuration is not None:
                spec.validate_configuration(params,data)
            status=runtime_status[spec.role]
            if not status["runtime_available"]:
                errors.append(f"{spec.role}: {status['runtime_reason']}")
        if not hs.two_level: errors.append("HIBE lacks two-level delegation")
        if (hs.test_only or ins.test_only) and not data["allow_mock"]:
            errors.append("TEST-ONLY mock selection requires explicit allow_mock=true")
        if data["signature_format"] not in ins.signature_formats:
            errors.append("signature format is not supported by the selected IBS; no fallback")
        if data["protocol"] not in ("byteauth-v1","baseline-v1"):
            errors.append("unknown protocol version")
        if data["state_policy"]!=STATE_POLICY:
            errors.append("unsupported state policy; fixed identity cache requires committed single-writer state")
        # Bounds on the legacy matrix engines prevent JSON profiles from
        # requesting unbounded allocation. They are resource policy, not
        # formal lattice security parameters. New parameter types own theirs.
        for role,spec,params in (("HIBE",hs,hp),("IBS",ins,ip)):
            if isinstance(params,Params):
                if (params.n>64 or params.m_matrix>8192 or params.identity_bytes>256
                        or params.max_message_bytes>65536 or len(params.name.encode("utf-8"))>128
                        or max(params.s0,params.s,params.s_prime)>2**20):
                    raise InvalidParameterError(f"{role}: legacy assembly resource budget exceeded")
                if not spec.test_only:
                    from ibme.lattice.gadget import gadget_width
                    if params.m_matrix<=params.n*gadget_width(params.q):
                        errors.append(f"{role}: parameters leave no trapdoor base columns")
        identity=hp.identity_bytes; payload=hp.max_message_bytes
        if data["transport"]=="hybrid":
            if not hs.key_binding: errors.append("Hybrid requires HIBE public key-binding validation")
            limits=data["hybrid_limits"]
            if set(limits)!={"backend_id","identity_max_bytes","max_payload_bytes","max_capsule_bytes"}:
                raise InvalidParameterError("wrong hybrid limit fields")
            if limits["backend_id"]!=hs.version:
                errors.append("Hybrid backend identifier/version mismatch")
            for name,upper in (("identity_max_bytes",256),("max_payload_bytes",16*2**20),("max_capsule_bytes",4*2**20)):
                if type(limits[name]) is not int or not 1<=limits[name]<=upper:
                    raise InvalidParameterError(f"invalid Hybrid {name}")
            identity=limits["identity_max_bytes"]; payload=limits["max_payload_bytes"]
            if hp.identity_bytes!=22+identity: errors.append("Hybrid inner identity capacity must equal encoded width")
            if hp.max_message_bytes<32: errors.append("Hybrid inner HIBE cannot hold the 32-byte seed")
            if importlib.util.find_spec("cryptography") is None:
                raise InvalidParameterError("Hybrid requires installed cryptography extra")
            capsule=hs.ciphertext_size(hp,32,hp.identity_bytes)
            if capsule>limits["max_capsule_bytes"]:
                errors.append("Hybrid capsule budget cannot contain the selected HIBE seed ciphertext")
            from ibme.protocol.hybrid_hibe import MAGIC, SUITE, CONTEXT_BYTES, NONCE_BYTES, TAG_BYTES
            hibe_wire=(len(MAGIC)+4+len(SUITE)+4+len(b"CIPHERTEXT")+16
                       +CONTEXT_BYTES+capsule+NONCE_BYTES+payload+TAG_BYTES)
        elif data["transport"]!="direct":
            raise InvalidParameterError("unknown transport version")
        else:
            capsule=hs.ciphertext_size(hp,payload,hp.identity_bytes)
            hibe_wire=capsule
            if data["hybrid_limits"]!={}: errors.append("direct suite must not carry Hybrid limits")
        baseline_wire=hibe_wire+len(MAGIC_CIPHERTEXT)+4
        if baseline_wire>MAX_INNER_BYTES:
            errors.append("selected ciphertext including Baseline frame exceeds 64 MiB assembly wire budget")
        identity=min(identity,getattr(ip,"identity_max_bytes",getattr(ip,"identity_bytes",0)))
        if not 1<=identity<=256: errors.append("shared identity capacity must be in [1,256]")
        ibs_input=getattr(ip,"message_max_bytes",getattr(ip,"max_message_bytes",0))
        envelope=ENVELOPE_OVERHEAD if data["protocol"]=="byteauth-v1" else 0
        signature=ins.signature_size(ip,data["signature_format"])
        signed_overhead=len(encode_message(b"x"*identity,b""))+envelope
        payload_overhead=len(DOMAIN_SIGNATURE)+8+signature+envelope
        maximum=min(ibs_input-signed_overhead,payload-payload_overhead)
        if maximum<0: errors.append("capacity insufficient even for an empty application message")
        capacity=dict(identity_bytes=identity,max_application_bytes=max(0,maximum),signature_max_bytes=signature,
                      ibs_input_bytes=ibs_input,hibe_payload_bytes=payload,protocol_payload_overhead=payload_overhead,
                      signed_input_overhead=signed_overhead,inner_hibe_payload_bytes=32 if data["transport"]=="hybrid" else payload,
                      inner_hibe_identity_bytes=hp.identity_bytes,inner_hibe_ciphertext_max_bytes=capsule)
        metadata.update(test_only=hs.test_only or ins.test_only,
                        state_policy=data["state_policy"],suite_digest=config.digest,
                        hibe=data["hibe"],ibs=data["ibs"],protocol=data["protocol"],transport=data["transport"],
                        signature_format=data["signature_format"],hibe_key_binding_capability=hs.key_binding,
                        raw_object_parameter_binding={"hibe":hs.object_parameter_binding,
                                                      "ibs":ins.object_parameter_binding},
                        resource_policy="legacy-assembly-resource-v1")
    except (IBMEError,TypeError,ValueError,AttributeError,OverflowError) as exc:
        errors.append(str(exc))
    return CompatibilityReport(not errors,tuple(errors),capacity,metadata)


@dataclass(frozen=True)
class _Decoder:
    reader: object
    check: object
    def from_bytes(self, data):
        value=self.reader.from_bytes(data)
        if value.to_bytes()!=data: raise SerializationError("noncanonical component encoding")
        self.check(value)
        return value


class _BoundedProtocol:
    """Input-only guards run before any IBS or OTS entropy is consumed."""
    security_claim = "none"
    backend_admitted = False
    parameters_are_formal = False
    def _bind(self, runtime): self._runtime=runtime
    def setup(self, params, *, ibs_params=None, rng=None):
        if params!=self._runtime.hibe_params or ibs_params!=self._runtime.ibs_params:
            raise InvalidParameterError("setup parameters differ from explicit suite")
        return super().setup(params,ibs_params=ibs_params,rng=rng)
    def skgen(self, master, sender_id):
        validate_identity(sender_id,max_bytes=self._runtime.capacity["identity_bytes"])
        self._runtime._validate_master_profile(master)
        return super().skgen(master,sender_id)
    def rkgen(self, master, receiver_id, *, rng=None):
        validate_identity(receiver_id,max_bytes=self._runtime.capacity["identity_bytes"])
        self._runtime._validate_master_profile(master)
        return super().rkgen(master,receiver_id,rng=rng)
    def encrypt(self, public, ek, receiver_id, message, *, rng=None):
        if not isinstance(public,PublicKey) or not isinstance(ek,SenderKey):
            raise TypeError("expected public/sender protocol objects")
        validate_identity(receiver_id,max_bytes=self._runtime.capacity["identity_bytes"])
        validate_identity(ek.identity,max_bytes=self._runtime.capacity["identity_bytes"])
        message=validate_bytes(message,name="application message")
        if len(message)>self._runtime.capacity["max_application_bytes"]:
            raise InvalidParameterError("application message exceeds selected suite capacity")
        self._runtime.validate_sender(public,ek)
        return super().encrypt(public,ek,receiver_id,message,rng=rng)
    def decrypt(self, public, dk, sender_id, ciphertext, *, rng=None):
        if not isinstance(public,PublicKey) or not isinstance(dk,ReceiverKey):
            raise TypeError("expected public/receiver protocol objects")
        validate_identity(sender_id,max_bytes=self._runtime.capacity["identity_bytes"])
        try:
            self._runtime.validate_receiver(public,dk)
        except IBMEError:
            return BOTTOM
        return super().decrypt(public,dk,sender_id,ciphertext,rng=rng)


class _Baseline(_BoundedProtocol,BaselineIBME): pass
class _Byteauth(_BoundedProtocol,ByteAuthenticatedIBME): pass


@dataclass
class SuiteRuntime:
    config: SuiteConfig
    proto: object
    hibe_params: object
    ibs_params: object
    decoders: dict
    capacity: dict
    metadata: dict
    hibe: object
    ibs: object
    ibs_master_public_key: object

    def _validate_public(self,public):
        for name,obj in (("hpk",public.hpk),("ipk",public.ipk)):
            self.decoders[name].from_bytes(obj.to_bytes())

    def _hibe_binding(self,public,secret):
        if self.config.transport=="hybrid":
            if secret.public_key.to_bytes()!=public.to_bytes():
                return False
            return self.hibe.inner_backend.validate_key_binding(public.inner,secret.inner) is True
        validator=getattr(self.hibe,"validate_key_binding",None)
        # This capability is optional for a direct backend. Absence is
        # reported by metadata, never silently advertised as validation.
        if not callable(validator): return None
        return validator(public,secret) is True

    def _validate_master_profile(self,master):
        if not isinstance(master,MasterSecret): raise TypeError("expected protocol master")
        for name,obj in (("hmsk",master.hmsk),("imsk",master.imsk)):
            self.decoders[name].from_bytes(obj.to_bytes())

    def validate_sender(self,public,sender):
        self._validate_public(public)
        key=self.decoders["sk"].from_bytes(sender.signing_key.to_bytes())
        validate_identity(sender.identity,max_bytes=self.capacity["identity_bytes"])
        if hasattr(key,"public_key") and key.public_key.to_bytes()!=public.ipk.to_bytes():
            raise SerializationError("sender key belongs to a different IBS public key")

    def validate_receiver(self,public,receiver):
        self._validate_public(public)
        key=self.decoders["sk1"].from_bytes(receiver.level1_key.to_bytes())
        validate_identity(receiver.identity,max_bytes=self.capacity["identity_bytes"])
        if self._hibe_binding(public.hpk,key) is False:
            raise SerializationError("receiver key belongs to a different HIBE public key")

    def validate_master(self, public, master):
        """Check encoded parameters and public binding, not generation provenance.

        Legacy wire omits some policy/generation fields. Only the CLI v2 state
        envelope binds these objects to every SuiteConfig field on disk.
        """
        if not isinstance(public,PublicKey) or not isinstance(master,MasterSecret):
            raise SerializationError("expected public/master protocol objects")
        # Invoke the selected primitive's public capability; never read trapdoors.
        if self._hibe_binding(public.hpk,master.hmsk) is False:
            raise SerializationError("HIBE master is not bound to the selected public key")
        if self.ibs_master_public_key(master.imsk).to_bytes()!=public.ipk.to_bytes():
            raise SerializationError("IBS master is not bound to the selected public key")
        for name,obj in (("hpk",public.hpk),("ipk",public.ipk),("hmsk",master.hmsk),("imsk",master.imsk)):
            self.decoders[name].from_bytes(obj.to_bytes())


def build_runtime(config, *, ibs_rng=None, ots_rng=None, registry=None):
    registry=registry or default_registry()
    report=validate_suite(config,registry=registry)
    if not report.ok: raise InvalidParameterError("; ".join(report.errors))
    data,hs,ins,hp,ip=_resolve(config,registry)
    hibe=hs.factory(None,"reference"); ibs=ins.factory(ibs_rng,data["signature_format"])
    if hs.key_binding and not callable(getattr(hibe,"validate_key_binding",None)):
        raise InvalidParameterError("registered HIBE did not provide its declared key-binding capability")
    readers={name:_Decoder(reader,lambda obj:hs.check_object(obj,hp)) for name,reader in hs.decoders.items()}
    hparams=hp
    if data["transport"]=="hybrid":
        from ibme.protocol.hybrid_hibe import HybridHIBE,HybridLimits,HybridHIBEParams
        values=dict(data["hybrid_limits"]); values["backend_id"]=values["backend_id"].encode("ascii")
        limits=HybridLimits(**values)
        hibe=HybridHIBE(hibe,backend_id=limits.backend_id,public_key_type=hs.decoders["hpk"],master_type=hs.decoders["hmsk"],
                        level1_type=hs.decoders["sk1"],level2_type=hs.decoders["sk2"])
        hparams=HybridHIBEParams(hp,limits)
        def check_limits(obj):
            public=obj if hasattr(obj,"limits") else obj.public_key
            if public.limits!=limits: raise SerializationError("object Hybrid limits differ from selected suite")
            hs.check_object(public.inner,hp)
            if obj is not public: hs.check_object(obj.inner,hp)
        readers={name:_Decoder(reader,check_limits) for name,reader in hibe.component_decoders().items()}
    readers.update({name:_Decoder(reader,lambda obj:ins.check_object(obj,ip)) for name,reader in ins.decoders.items()})
    proto=(_Byteauth(hibe,ibs,ots_rng=ots_rng) if data["protocol"]=="byteauth-v1" else _Baseline(hibe,ibs))
    runtime=SuiteRuntime(config,proto,hparams,ip,readers,report.capacity,report.metadata,hibe,ibs,ins.master_public_key)
    proto._bind(runtime)
    return runtime


__all__=["SuiteConfig","SuiteRuntime","CompatibilityReport","BackendSpec","BackendRegistry",
         "default_registry","make_suite","validate_suite","build_runtime","list_backends"]
