import Lake
open Lake DSL

package foolil4

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "d13f23b723b8a846827a245b89c10fc7d3f11612"

@[default_target]
lean_lib FooLiL4

lean_lib FooLiL3
lean_lib FooLiL2
