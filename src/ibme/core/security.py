"""Shared immutable spellings for coordinator-owned security of completed profiles."""

COMPLETED_SECURITY_CLAIM = "secure"
UNADMITTED_SECURITY = ("none", False, False)
ADMITTED_SECURITY = (COMPLETED_SECURITY_CLAIM, True, True)


def security_tuple(value):
    """Read the three common fields from an object or mapping."""
    if isinstance(value, dict):
        return tuple(value[name] for name in (
            "security_claim", "backend_admitted", "parameters_are_formal"))
    return value.security_claim,value.backend_admitted,value.parameters_are_formal


def security_fields(value):
    """Copy the selected snapshot's fields, including exact legacy snapshots."""
    return dict(zip(("security_claim", "backend_admitted", "parameters_are_formal"),
                    security_tuple(value), strict=True))
