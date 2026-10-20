"""Shared immutable spellings for coordinator-owned project admission."""

PROJECT_SECURITY_CLAIM = "project-admitted"
UNADMITTED_SECURITY = ("none", False, False)
ADMITTED_SECURITY = (PROJECT_SECURITY_CLAIM, True, True)


def security_tuple(value):
    """Read the three common fields from an object or mapping."""
    if isinstance(value, dict):
        return tuple(value[name] for name in (
            "security_claim", "backend_admitted", "parameters_are_formal"))
    return value.security_claim,value.backend_admitted,value.parameters_are_formal
