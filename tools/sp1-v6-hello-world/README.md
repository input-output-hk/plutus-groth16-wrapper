# sp1-v6-hello-world

Generates a real **SP1 v6.x** (sp1-sdk 6.2.4, circuit `v6.1.0`) Groth16/BN254
proof for the `multiply(17, 23)` guest and dumps its artifacts, to document the
current artifact format and feed the `zkwrap-sp1` rework. 

## Run it

```bash
cd experiments/sp1-v6-hello-world
export PATH="$HOME/.sp1/bin:$PATH"          # SP1 toolchain (cargo-prove) on PATH
export CARGO_TARGET_DIR=$HOME/.sp1v6-target # optional: isolate the heavy build
cargo run --release --bin dump_groth16
```

To skip recompiling the guest (it's already built once), add:

```bash
export SP1_SKIP_PROGRAM_BUILD=true
```

Artifacts land in `fixtures/` (`proof_bytes.bin`, `raw_proof_256.bin`,
`public_values.bin`, `exit_code.bin`, `vk_root.bin`, `proof_nonce.bin`,
`groth16_vk.bin`, `manifest.json` — the 5 public inputs + layout).

## Prerequisites

- **SP1 toolchain** (`cargo-prove`): `curl -L https://sp1.succinct.xyz | bash && sp1up`
- **Go + GCC** — `native-gnark` compiles the gnark FFI via CGO at build time.
- **Disk + network** — first run downloads the **3.2 GB** v6.1.0 circuit
  artifacts to `~/.sp1/circuits/groth16/v6.1.0/` (cached after).
- **No GPU / no prover network** — proving is local CPU.

## Timing (CPU, this box)

- First build: ~15 min (Plonky3 + OpenSSL-from-source + native-gnark CGO).
- Artifact download: one-time, 3.2 GB.
- Per run: ~1.5 min proving-key load + ~3 min Groth16 prove.

## What it confirmed

Circuit `v6.1.0` has **5** Groth16 public inputs (v3.0.0 had 2):
`[vkey_hash, committed_values_digest, exit_code, vk_root, proof_nonce]`.
