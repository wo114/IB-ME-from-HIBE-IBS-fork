"""Explicit standalone paper-order backend, preserving the joint baseline."""
from fractions import Fraction

from experiments.research.gaussian_reference import SamplingAbort
from .paper_backend import Backend
from .aggregate_budget import AggregateByteSource
from .paper_algebra import PaperRing, identity_target, message_challenge
from .paper_objects import SigningKey, Signature, _message
from .structured_execution import _norm
from .paper_schur_samplef import PaperSchurSampleF
from .structured_geometry import master_operator, signature_operator


class SourceSchurBackend(Backend):
    """Paper-order source-Schur backend with the complete gate set built in.

    Setup runs SchurNumericalAudit, the finite-chain source gates, the issuance
    C gate and the finite-key object/service envelope; a gate failure is a root
    rejection (retry).  Signing runs the Schur/audit layer; a fixed-key gate
    failure aborts.  The complete gate set is the protected accept set; the
    original unguarded algorithm is not claimed to pass it.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.gate_rejections = 0
        self.last_master_gate_audit = None
        self.last_sign_gate_audit = None
        self.last_master_gate_extras = None
        self.last_sign_gate_extras = None

    def _sign_attempt_source(self, params, plan, scalar):
        from .paper_sign_budget import signature_attempt_certificate, signature_call_envelope
        self.last_sign_attempt_certificate = signature_attempt_certificate(
            params, plan.byte_cap, scalar, error_bits=self.series_options.aggregate_abort_bits)
        if not self.last_sign_attempt_certificate["admitted"]:
            raise ValueError("source-Schur full signature-attempt entropy cap exceeds budget")
        self.last_sign_attempt_certificate["cap_installed_by_backend"] = True
        self.last_sign_call_certificate = signature_call_envelope(
            self.last_sign_attempt_certificate, max_attempts=self.sign_max_attempts)
        return AggregateByteSource(self.rng, self.last_sign_attempt_certificate["selected_cap_bytes"])

    def sign(self, key, message):
        # Keep the frozen joint implementation byte-for-byte. This explicit
        # Algorithm 7 path changes only the separately charged entropy cap.
        if type(key) is not SigningKey:
            raise TypeError("paper SigningKey required")
        message = _message(message)
        public, p = key.public_key, key.public_key.params
        ring, (_, scalar) = PaperRing(p), self._components(p)
        plan = self._sign_plan(key)
        self.last_sign_certificate = plan.public_certificate()
        target = identity_target(public, key.identity)
        for _ in range(self.sign_max_attempts):
            self.sign_attempts += 1
            source = self._sign_attempt_source(p, plan, scalar)
            flat = plan.sample(rng=source)
            perturbation = tuple(tuple(flat[i:i+p.degree]) for i in range(0, len(flat), p.degree))
            commitment = ring.matvec(ring.signing_matrix(public, target), perturbation, 2*p.modulus)
            challenge = message_challenge(public, commitment, message)
            centers = tuple(Fraction(-x, 2) for x in ring.multiply(ring.zeta(True), challenge))
            u = tuple(int(scalar.sample(p.r_squared, center, rng=source)) for center in centers)
            response = ring.response(key.full, perturbation, u, challenge)
            if _norm(response) > p.signature_norm_cap:
                continue
            result = Signature(public.context, response, challenge)
            if not self.verify(public, key.identity, message, result):
                raise RuntimeError("source-Schur honest commitment invariant failed")
            return result
        raise SamplingAbort("paper Algorithm 7 exhausted the operational sign limit")

    def _master_plan(self, params, witness):
        plan = PaperSchurSampleF(master_operator(degree=params.degree, rank=params.rank,
            digits=params.digits, base=params.base, witness=witness,
            first_squared=params.master_first_squared, second_squared=params.master_second_squared,
            r_squared=params.r_squared), options=self.series_options, scalar_options=self.scalar_options)
        from .paper_distribution_guard import (
            GateFailure, RootGateRejection, require_gates,
        )
        try:
            gadget, _scalar = self._components(params)
            audit, _degree, _leaves, extras = require_gates(
                plan, params=params, gadget=gadget, root_phase=True)
        except GateFailure as error:
            self.gate_rejections += 1
            raise RootGateRejection("Setup audit gate rejected root: " + str(error)) from error
        self.last_master_gate_audit = audit
        self.last_master_gate_extras = extras
        return plan

    def _sign_plan(self, key):
        p = key.public_key.params
        plan = PaperSchurSampleF(signature_operator(degree=p.degree, rank=p.rank, digits=p.digits,
            user_vector=key.full, first_squared=p.signature_first_squared,
            second_squared=p.signature_second_squared, r_squared=p.r_squared,
            noise_factor=1), options=self.series_options, scalar_options=self.scalar_options)
        from .paper_distribution_guard import (
            GateFailure, SigningKeyGateRejection, require_gates,
        )
        try:
            audit, _degree, _leaves, extras = require_gates(plan)
        except GateFailure as error:
            raise SigningKeyGateRejection("signing-key audit gate failed: " + str(error)) from error
        self.last_sign_gate_audit = audit
        self.last_sign_gate_extras = extras
        return plan
