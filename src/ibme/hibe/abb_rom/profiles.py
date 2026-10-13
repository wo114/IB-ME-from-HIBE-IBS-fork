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


def q76_normalized_root_research_params():
    """Public screened full profile; root quality is a mandatory actual gate."""
    return replace(ABBROMParams(),name="abb-rom-ap09-n1-q76-normalized-root-research",
        q=37778931862957161709601,random_rows=152,root_m1=152,root_m2=456,
        hadamard_scale=33,matrix_gaussian_squared_width=4800,
        sigma1_squared=244228428595200,
        sigma2_squared=2266605962695066791727595520000,
        tau2_squared=413428927595580182811113422848000000,
        epsilon_bits=64,max_parents=2,max_children_per_parent=2,
        normalization="matrix-flatter-rootgs16-lll-075-exact074-v3")


def q80_normalized_root_research_params():
    return replace(ABBROMParams(),name="abb-rom-ap09-n1-q80-normalized-root-research",
        q=604462909807314587353111,random_rows=160,root_m1=160,root_m2=480,
        hadamard_scale=35,matrix_gaussian_squared_width=76800,
        sigma1_squared=70401895956480000,
        sigma2_squared=12391067385667587435134976000000000,
        tau2_squared=2379084938048176787545915392000000000000,
        epsilon_bits=64,max_parents=2,max_children_per_parent=2,
        normalization="matrix-flatter-rootgs256-nativegram-exact074-v4")


def q22_all_level_research_params():
    """Full lengths, with actual quality gates at root AND both issued levels.

    This n=1 negative control is a functional research instance. Acceptance
    conditioning and formal high-n parameters remain unproved.
    """
    return replace(ABBROMParams(),name="abb-rom-ap09-n1-q22-all-level-quality-research",
        q=2097169,random_rows=44,root_m1=44,root_m2=132,hadamard_scale=20,
        matrix_gaussian_squared_width=74752,
        sigma1_squared=5044531837796352,sigma2_squared=5044531837796352,
        tau2_squared=74752,epsilon_bits=64,max_parents=2,max_children_per_parent=2,
        normalization="matrix-flatter-allgs256-nativegram-exact074-v5")


def q26_level_quality_research_params():
    """Separate complete recipe with a fixed 2^16 parent/leaf quality gate."""
    return replace(ABBROMParams(),name="abb-rom-ap09-n1-q26-level-quality-research",
        q=33554467,random_rows=52,root_m1=52,root_m2=156,hadamard_scale=23,
        matrix_gaussian_squared_width=74752,sigma1_squared=7045668434608128,
        sigma2_squared=1803691119259680768,tau2_squared=19136512,
        epsilon_bits=64,max_parents=2,max_children_per_parent=2,
        normalization="matrix-flatter-rootgs256-levelgs65536-nativegram-exact074-v6")
