"""Explicit portable research selection after the public same-input screen.

The single-address profile fits a 32 B capsule inside the existing 4 MiB
Hybrid limit. It is an n=1 security negative control, not a safe preset.
No runtime failure chooses this profile or regenerates an existing address.
"""

from dataclasses import replace
from .params import ABBROMParams


def q104_research_params():
    return replace(ABBROMParams(),name="abb-rom-ap09-n1-q104-single-address-research",
        q=10141204801825835211973625643089,random_rows=208,root_m1=208,root_m2=624,
        hadamard_scale=46,matrix_gaussian_squared_width=277673628,
        sigma1_squared=1623986518409894312214528,
        sigma2_squared=4393678979852224267713637199190156629954789376,
        tau2_squared=2032480746647800128450186859247772935764045927022592,
        max_parents=1,max_children_per_parent=1)


def q104_flatter_research_params():
    """Same widths/noise; fixed external reduction for a separate instance."""
    return replace(q104_research_params(),name="abb-rom-ap09-n1-q104-flatter-research",
        normalization="matrix-flatter-lll-075-0501-exact074-v2")
