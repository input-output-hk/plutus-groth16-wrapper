# Expose inner public inputs as direct outer public inputs

Inner public inputs from the BN254 Groth16 proof are exposed directly as outer BLS12-381 public inputs (`[VKHash, input_0, ..., input_{MAX-1}]`), rather than being hashed into an `InputCommitment`.

The commitment approach was considered: the outer circuit computes `InputCommitment = hash(inputs)` in-circuit, and the Aiken validator receives the raw inputs and recomputes the hash on-chain to verify soundness. This was rejected for two reasons: (1) the hash function must be efficient both as gnark in-circuit constraints and as Cardano Plutus builtins — Poseidon is cheap in gnark but has no Cardano builtin; SHA-256 has a Cardano builtin but is expensive in gnark (≥100k extra constraints); (2) an Aiken validator that only receives `InputCommitment` cannot enforce application logic on the individual inputs without an on-chain hash recomputation.

With direct exposure, the outer Groth16/BLS12-381 proof itself binds the public inputs — no on-chain hash is needed and soundness comes from the proof. Aiken validators receive the inputs directly from the outer proof's public inputs vector and can apply app logic without further verification steps.
