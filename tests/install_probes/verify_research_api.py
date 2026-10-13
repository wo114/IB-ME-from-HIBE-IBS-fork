"""Execute with python -I outside the checkout, against an installed wheel.

The only added import root is the explicit pip installation, never repository
src/ or experiments/. Saved fixtures are data, not imported Python providers.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


class NoEntropy:
    def read(self,count):raise AssertionError("restoration/reuse unexpectedly requested entropy")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--install-root",type=Path,required=True)
    p.add_argument("--checkout",type=Path,required=True)
    p.add_argument("--fixtures",type=Path)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    install=a.install_root.resolve();checkout=a.checkout.resolve()
    assert sys.flags.isolated==1
    assert not Path.cwd().resolve().is_relative_to(checkout)
    assert not any(Path(x).resolve().is_relative_to(checkout) for x in sys.path if x)
    sys.path.insert(0,str(install))
    import ibme
    from ibme.hibe import mp12_chkp
    from ibme.lattice import research
    assert "sage.all" not in sys.modules
    assert Path(ibme.__file__).resolve().is_relative_to(install)
    from ibme.assembly import default_registry,SuiteConfig,build_runtime
    from ibme.core.errors import InvalidParameterError
    checks={"isolated_outside_checkout":True,"plain_import_without_sage_all":True}
    os.environ.pop(mp12_chkp.ENGINE_ENV,None)
    spec=default_registry().get("hibe",mp12_chkp.BACKEND_ID)
    if not research.sage_available():
        assert not spec.available and spec.factory is None
        checks["no_sage_explicit_unavailable"]=True
    else:
        assert spec.available
        from ibme.lattice.research import FirstFiniteGaussian
        from ibme.hibe.mp12_chkp import MP12HIBEParams
        from ibme.core.randomness import DeterministicRandom
        scalar=FirstFiniteGaussian(16,16)
        value=scalar.sample(16,0,rng=DeterministicRandom(b"installed-public-scalar-test-only"))
        assert type(value) is int
        checks["actual_finite_gaussian_public_api"]=True
        backend=spec.factory(None,"reference")
        try:backend.setup(MP12HIBEParams(),rng=NoEntropy())
        except InvalidParameterError:checks["missing_engine_setup_rejected_before_entropy"]=True
        else:raise AssertionError("missing engine unexpectedly generated root")
        if a.fixtures is None:raise ValueError("actual saved lifecycle required under Sage")
        from ibme.protocol.baseline import PublicKey,MasterSecret,ReceiverKey,SenderKey,is_bottom
        fixtures=a.fixtures.resolve()
        config=SuiteConfig.from_json((fixtures/"suite.json").read_bytes())
        runtime=build_runtime(config)
        public=PublicKey.from_bytes((fixtures/"public.bin").read_bytes(),runtime.decoders["hpk"],runtime.decoders["ipk"])
        master=MasterSecret.from_bytes((fixtures/"master-final.bin").read_bytes(),runtime.decoders["hmsk"],runtime.decoders["imsk"])
        root_master=MasterSecret.from_bytes((fixtures/"master-root.bin").read_bytes(),runtime.decoders["hmsk"],runtime.decoders["imsk"])
        before=root_master.to_bytes()
        try:runtime.proto.rkgen(root_master,b"new-address",rng=NoEntropy())
        except InvalidParameterError:pass
        else:raise AssertionError("missing engine unexpectedly generated receiver")
        assert root_master.to_bytes()==before
        checks["missing_engine_new_receiver_no_entropy_or_state_change"]=True
        receivers={name:ReceiverKey.from_bytes((fixtures/file).read_bytes(),runtime.decoders["sk1"])
            for name,file in [("Bob","bob.bin"),("Mallory","mallory.bin")]}
        sender=SenderKey.from_bytes((fixtures/"alice.bin").read_bytes(),runtime.decoders["sk"])
        runtime.validate_master(public,master)
        runtime.validate_sender(public,sender)
        for receiver in receivers.values():runtime.validate_receiver(public,receiver)
        ct=(fixtures/"ciphertext.bin").read_bytes()
        expected=b"A-reference complete IBME lifecycle, not a security claim"
        for receiver,sender_id in [("Bob",b"Alice"),("Bob",b"Eve"),("Mallory",b"Alice"),("Mallory",b"Eve")]:
            result=runtime.proto.decrypt(public,receivers[receiver],sender_id,ct,rng=NoEntropy())
            assert result==expected if (receiver,sender_id)==("Bob",b"Alice") else is_bottom(result)
            checks[f"saved_{receiver}_{sender_id.decode()}"]=True
        cached=runtime.proto.rkgen(master,b"Bob",rng=NoEntropy())
        assert cached.to_bytes()==receivers["Bob"].to_bytes()
        assert master.to_bytes()==(fixtures/"master-final.bin").read_bytes()
        checks["master_and_receiver_cache_canonical_no_generation"]=True
    providers={}
    for name,module in sorted(sys.modules.items()):
        if name=="ibme" or name.startswith(("ibme.","experiments.")):
            filename=getattr(module,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                assert path.is_relative_to(install),(name,str(path))
                providers[name]=str(path.relative_to(install))
    result=dict(schema="A-INSTALLED-PUBLIC-API/1",python=sys.version.split()[0],
        sage_available=research.sage_available(),isolated=True,cwd_outside_checkout=True,
        import_provider_files=providers,checks=checks,checks_passed=sum(checks.values()),
        engine_environment_configured=False,new_root_parent_or_leaf_generations=0,
        source_fixtures_only_data=True,security_claim="none",backend_admitted=False,
        parameters_are_formal=False,limitations=["n2 known public attack remains","no formal model/parameter admission"])
    if a.output.exists():raise ValueError("new public receipt path required")
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open("x",encoding="utf-8") as f:f.write(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"checks_passed":result["checks_passed"],"installed_providers":len(providers),
        "sage":result["sage_available"],"new_generations":0}));return 0


if __name__=="__main__":raise SystemExit(main())
