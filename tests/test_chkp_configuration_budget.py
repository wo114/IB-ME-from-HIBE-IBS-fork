"""Shared assembly noise gates, with no primitive execution or Sage imports."""

from dataclasses import replace
from fractions import Fraction

import pytest

from ibme.assembly import BackendRegistry, build_runtime, default_registry, make_suite, validate_suite
from ibme.core.errors import InvalidParameterError
from ibme.hibe.chkp import research_params
from ibme.lattice.chkp.joint_parameters import evaluate_noise


def configuration_registry():
    registry = default_registry()

    def no_factory(*a, **k):
        pytest.fail('configuration rejection must precede runtime construction')

    # Remove the installation gate only. The production CHKP parameter hook
    # remains intact; no cryptographic algorithm is replaced or executed.
    return BackendRegistry([
        replace(registry.get('hibe', 'chkp'), validate_environment=None, factory=no_factory),
        registry.get('ibs', 'luo-module'),
    ])


def selected(params, registry):
    return make_suite(hibe='chkp', ibs='luo-module', transport='hybrid',
                      hibe_params=params, registry=registry)


def test_frozen_noise_budget_stays_accepted_without_security_upgrade():
    registry = configuration_registry()
    params = research_params()
    report = validate_suite(selected(params, registry), registry=registry)
    assert report.ok
    assert report.metadata['security_claim'] == 'none'
    assert report.metadata['backend_admitted'] is False
    assert report.metadata['parameters_are_formal'] is False
    budget = evaluate_noise(q=params.q, dimension=params.leaf_dimension,
                            width_squared=params.leaf_width_squared, alpha=params.alpha,
                            error_bits=64, seed_bits=256, encapsulations=2**20)
    assert budget['conditional_noise_sufficient'] is True
    assert Fraction(budget['conditional_lifetime_failure_upper']) == Fraction(1, 2**36)
    assert budget['noise_implementation_verified'] is False


@pytest.mark.parametrize('change', [
    {'alpha_numerator': 128}, {'alpha_numerator': 512},
    {'leaf_width_squared': research_params().leaf_width_squared * 2**20},
])
def test_custom_diagnostic_profile_cannot_bypass_protocol_noise_budget(change):
    # The primitive profile remains available for explicit diagnostics.
    params = replace(research_params(), **change)
    registry = configuration_registry()
    suite = selected(params, registry)
    report = validate_suite(suite, registry=registry)
    assert not report.ok
    error = '; '.join(report.errors)
    assert 'conditional decoding sufficient gate' in error
    assert 'error_bits=64, seed_bits=256, encapsulations=2^20' in error
    with pytest.raises(InvalidParameterError, match='conditional decoding sufficient gate'):
        build_runtime(suite, registry=registry)


def test_public_noise_support_cap_is_checked_without_building_distribution():
    params = replace(research_params(), noise_max_radius=1)
    registry = configuration_registry()
    report = validate_suite(selected(params, registry), registry=registry)
    assert not report.ok
    assert any('support exceeds public radius budget' in error for error in report.errors)
