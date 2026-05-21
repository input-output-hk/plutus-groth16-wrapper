# Universal wrapper circuit with configurable MAX_INPUTS

A single wrapper circuit is compiled with a hardcoded `MAX_INPUTS` constant rather than one circuit per inner proof system. Systems with fewer real inputs (e.g., SP1 with 2 vs RISC Zero with 5) pad their canonical inner proof with zero-valued inputs up to `MAX_INPUTS`. The Aiken validator for each inner system enforces that the excess slots equal zero.

The alternative (a separate circuit and trusted setup ceremony per inner proof system) was rejected because it multiplies ceremony overhead with every new inner system added. A single ceremony is far more practical to organise and audit.

`MAX_INPUTS` is a compile-time constant to be chosen after benchmarking the constraint cost of additional public input slots in the wrapper circuit. It should be set generously enough to cover foreseeable inner proof systems without requiring a new ceremony, but not so large that proving time or on-chain verification cost is affected materially. The value is not fixed in this ADR; it will be recorded here once benchmarked.

**Soundness note:** for inner systems that pad with zeros, the Aiken validator must explicitly check that the padded input slots equal zero. This check cannot be omitted: if the inner VK is a private witness (as it is in the current gnark `std/recursion/groth16` design), an adversary could supply a padded VK with non-identity IC points for the zero-input slots and pass the pairing check with arbitrary values in those slots.
