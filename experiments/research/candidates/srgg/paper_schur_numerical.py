"""Directed local numerical certificates for the sequential paper sampler.

This auditor starts again from the exact fixed geometry, encloses the ideal
ring-Schur pivots/gains, and compares the *stored* dyadic gains and Fourier
square-root factors.  If E_j bounds a numerical-vs-ideal conditional-center
coefficient error, epsilon_j bounds each coefficient of Khat_j-K_j, and B_i
bounds every successful sampled residual x_i-chat_i, then

 E'_j <= E_j + n*epsilon_j*B_i
              + (||Khat_j||_1+n*epsilon_j)*E_i + 2^(-dyadic_bits-1).

Negacyclic multiplication is a signed convolution, so its coefficient
infinity norm is bounded by coefficient l1 times infinity norm.  The recurrence
couples the two chains at the SAME lower vector and sampled upper history;
it is not a coupling of their complete probability distributions.

For ideal mathematical FFT application of stored factors a_k, the continuous
covariance eigenvalues are a_k^2.  Directed enclosures compare those with
(f_k-r^2)/(2*pi).  Actual finite FFT arithmetic is checked only for explicitly
provided vectors.  Finite Box--Muller, all-input arithmetic, integer rounding,
aborts and a sequential-law TV bound remain separate obligations.
"""

from copy import deepcopy
from fractions import Fraction

from sage.all import ComplexIntervalField, QQ, ZZ

from .paper_schur_fourier import conjugate_extension, forward, inverse
from .paper_schur_samplef import PaperSchurSampleF


def _bounded(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("bounded exact integer required: "+label)
    return value


def _exact(value):
    if isinstance(value, bool) or not isinstance(value, (int, Fraction, type(ZZ(0)), type(QQ(0)))):
        raise ValueError("exact rational coefficient required")
    result = QQ(value.numerator)/value.denominator if isinstance(value, Fraction) else QQ(value)
    if max(abs(int(result.numerator())).bit_length(), int(result.denominator()).bit_length()) > 4096:
        raise ValueError("numerical audit rational resource limit exceeded")
    return result


def _upper_absolute(interval):
    return abs(interval).upper().exact_rational()


class SchurNumericalAudit:
    """No-entropy, fixed-witness certificate; private diagnostics are redacted."""

    def __init__(self, sampler, *, precision_bits=1024, gain_error_bits=128,
                 covariance_error_bits=128, center_error_bits=96):
        if type(sampler) is not PaperSchurSampleF:
            raise TypeError("prepared PaperSchurSampleF required")
        _bounded(precision_bits, "precision_bits", 192, 2048)
        for name, value in (("gain_error_bits", gain_error_bits),
                            ("covariance_error_bits", covariance_error_bits),
                            ("center_error_bits", center_error_bits)):
            _bounded(value, name, 32, 512)
        if precision_bits < sampler.options.precision_bits:
            raise ValueError("audit precision must cover the prepared sampler precision")
        self.sampler, self.geometry = sampler, sampler.geometry
        self.field = field = ComplexIntervalField(precision_bits)
        g, n, rows = self.geometry, self.geometry.degree, self.geometry.upper_polynomials
        if n > 512 or rows > 16 or g.lower_polynomials > 16:
            raise ValueError("sequential numerical audit dimension budget exceeded")
        if len(sampler.plan.stages) != rows or len(sampler.leaves) != rows:
            raise ValueError("prepared stage/leaf count mismatch")
        # Audit replay uses the exact supplied witness and the mathematical DFT
        # in directed intervals.  It does not trust stored pivot enclosures.
        spectra = [[forward(tuple(poly[i] for i in range(n)), field)[:n//2]
                    for poly in row] for row in g.witness]
        scale = g.noise_squared*g.lower_squared/g.lower_scalar
        matrices = []
        for k in range(n//2):
            matrices.append([[field(int(i == j)*g.top_squared[i])-scale*sum(
                (spectra[i][t][k]*spectra[j][t][k].conjugate()
                 for t in range(g.lower_polynomials)), field(0))
                for j in range(rows)] for i in range(rows)])
        errors, records = [QQ(0)]*rows, []
        self._stored_factor_rationals = []
        maximum_center_error = QQ(0)
        pivot_shape_floor64 = True
        for expected_index, stage, leaf in zip(reversed(range(rows)), sampler.plan.stages, sampler.leaves):
            if (stage.index != expected_index or leaf.geometry is not g
                    or len(stage.gains) != expected_index or len(leaf.factors) != n//2):
                raise ValueError("prepared stage/geometry binding mismatch")
            index, pivots = stage.index, []
            gains = [[] for _ in range(index)]
            updated = []
            for current in matrices:
                value = current[index][index]
                if not value.imag().contains_zero() or (value.real()-g.rounding_squared).lower() <= 0:
                    raise ValueError("ideal Schur pivot/rounding floor not certified")
                pivot = value.real()
                pivots.append(pivot)
                current_gains = [current[i][index]/pivot for i in range(index)]
                for target, gain in zip(gains, current_gains):
                    target.append(gain)
                updated.append([[current[i][j]-current_gains[i]*current[index][j]
                                 for j in range(index)] for i in range(index)])
            gain_errors, ideal_gain_l1 = [], []
            if any(pivot.lower().exact_rational() < 64 for pivot in pivots):
                pivot_shape_floor64 = False
            for stored, spectrum in zip(stage.gains, gains):
                if stored.degree() >= n:
                    raise ValueError("noncanonical prepared gain")
                coefficient_enclosures = inverse(conjugate_extension(spectrum), field)
                error = QQ(0)
                for i, enclosure in enumerate(coefficient_enclosures):
                    if not enclosure.imag().contains_zero():
                        raise ValueError("ideal gain real-coefficient enclosure failed")
                    error = max(error, _upper_absolute(enclosure.real()-stored[i]))
                if error > QQ(1)/2**gain_error_bits:
                    raise ValueError("prepared gain exceeds certified coefficient-error gate")
                gain_errors.append(error)
                ideal_gain_l1.append(sum(abs(stored[i]) for i in range(n))+n*error)
            factors, covariance_error = [], QQ(0)
            for stored, pivot in zip(leaf.factors, pivots):
                if stored.imag() != 0:
                    raise ValueError("real stored Fourier square-root factor required")
                factor = stored.real().exact_rational()
                factors.append(factor)
                target = (pivot-g.rounding_squared)/(2*field.real_field().pi())
                covariance_error = max(covariance_error, _upper_absolute(target-factor**2))
            if covariance_error > QQ(1)/2**covariance_error_bits:
                raise ValueError("stored Fourier factor exceeds ideal covariance-error gate")
            residual_cap = _exact(leaf.noise_cap)
            if residual_cap <= 0:
                raise ValueError("positive successful-residual envelope required")
            before = tuple(errors)
            errors = [error+n*epsilon*residual_cap+gain_l1*before[-1]
                      +QQ(1)/2**(sampler.options.vector_dyadic_bits+1)
                      for error, epsilon, gain_l1 in zip(before[:-1], gain_errors, ideal_gain_l1)]
            maximum_center_error = max([maximum_center_error]+errors)
            if maximum_center_error > QQ(1)/2**center_error_bits:
                raise ValueError("adaptive center recurrence exceeds certified error gate")
            records.append({"index": index, "gain_coefficient_errors": tuple(gain_errors),
                            "ideal_gain_coefficient_l1_upper": tuple(ideal_gain_l1),
                            "stored_factor_covariance_operator_error_upper": covariance_error,
                            "center_coefficient_errors_before": before,
                            "center_coefficient_errors_after": tuple(errors),
                            "successful_residual_coefficient_cap": residual_cap})
            self._stored_factor_rationals.append(tuple(factors))
            matrices = updated
        self._private = tuple(records)
        self._certificate = {
            "schema": "IBME/SRGG-SCHUR-LOCAL-NUMERICAL/1",
            "degree": n, "upper_polynomials": rows,
            "sampling_order": list(sampler.plan.sampling_order),
            "audit_precision_bits": precision_bits,
            "gain_coefficient_error_upper": "1/"+str(2**gain_error_bits),
            "stored_factor_ideal_covariance_operator_error_upper": "1/"+str(2**covariance_error_bits),
            "all_ideal_schur_pivot_eigenvalues_at_least_64": pivot_shape_floor64,
            "adaptive_center_coefficient_error_upper_on_same_successful_history": "1/"+str(2**center_error_bits),
            "center_recurrence_covers_all_successful_residuals_within_prepared_envelopes": True,
            "stored_factor_covariance_scope": "mathematical exact-trigonometric FFT applied to iid exact standard normal coefficients",
            "initial_center_comparison": "identical exact lower vector and exact initial geometry center",
            "witness_dependent_diagnostics_redacted": True,
            "entropy_bytes_consumed": 0,
            "finite_fft_arithmetic_all_inputs_error_upper": None,
            "finite_box_muller_to_ideal_normal_tv_upper": None,
            "full_target_integer_tv_upper_including_abort": None,
            "security_claim": "none", "backend_admitted": False,
            "parameters_are_formal": False, "nist_security_category": None,
        }

    def __repr__(self):
        return "SchurNumericalAudit(private_geometry_and_bounds=<redacted>)"

    def public_certificate(self):
        return deepcopy(self._certificate)

    def private_bounds(self):
        """Sensitive process-local values; not suitable for root/key receipts."""
        return deepcopy(self._private)

    def check_factor_application(self, stage_index, coefficients, *, error_bits=128):
        """Certify ONE explicit finite FFT evaluation, not every possible draw."""
        _bounded(stage_index, "stage_index", 0, len(self._private)-1)
        _bounded(error_bits, "error_bits", 32, 512)
        n, field = self.geometry.degree, self.field
        if not isinstance(coefficients, (tuple, list)) or len(coefficients) != n:
            raise ValueError("fixed-degree exact coefficient vector required")
        values = tuple(_exact(x) for x in coefficients)
        if max(abs(x) for x in values) > 4*(self.sampler.options.ticket_bits+1):
            raise ValueError("checked vector exceeds the successful normal-coordinate envelope")
        transformed = forward(values, field)
        factors = conjugate_extension(self._stored_factor_rationals[stage_index])
        ideal = inverse(tuple(value*factor for value, factor in zip(transformed, factors)), field)
        actual = self.sampler.leaves[stage_index].factor_apply(values)
        error = QQ(0)
        for output, reference in zip(actual, ideal):
            if not reference.imag().contains_zero():
                raise ValueError("ideal real factor-application enclosure failed")
            error = max(error, _upper_absolute(reference.real()-output.exact_rational()))
        if error > QQ(1)/2**error_bits:
            raise ValueError("explicit finite FFT evaluation exceeds the error gate")
        return {"scope": "one supplied coefficient vector only",
                "sampling_stage_index": self.sampler.plan.stages[stage_index].index,
                "coefficient_error_upper": "1/"+str(2**error_bits),
                "all_vectors_certified": False, "entropy_bytes_consumed": 0,
                "full_target_integer_tv_upper_including_abort": None}
