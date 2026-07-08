# Ethereum state on Cardano — RISC Zero Steel, end-to-end

A runnable showcase: prove a fact about **Ethereum state** — an ERC-20 balance,
read via [Steel](https://github.com/boundless-xyz/steel) inside the RISC Zero
zkVM — wrap the proof through the zkwrap pipeline, and enforce an app policy on
it from a Cardano validator.

The guest executes `balanceOf(account)` against verified Ethereum state
(block header + `eth_getProof` Merkle proofs checked against the state root)
and commits a journal with Steel's block commitment plus
`token / account / balance`. 

So the full proven claim is: "there exists a block with hash B (at height N, on a chain with config C) such that executing balanceOf(account) on token's code against B's state root returns X."

The pipeline ends with a green `aiken check` on an
**app validator** that unlocks only if the proven balance meets a threshold at
a datum-pinned Ethereum block.

```text
[1] preflight    balanceOf view call vs ETH_RPC_URL → EvmInput (header + MPT proofs)
[2] prove        Steel guest → RISC Zero Groth16 Receipt      (Docker stark2snark, ~7.5 min)
[3] canonicalize Receipt → CanonicalInnerProof                (re-verifies → binding)
[4] wrap         GnarkCliProver::prove → BLS12-381 OuterProof (gnark, ~40s)
[5] compose      generate Aiken verifier project → aiken check ✅
```

## The fork-and-extend workflow (what this example demonstrates)

Third-party integration is: **generate → copy → extend.**

1. The host writes the pristine, reproducible verifier project to
   `generated/steel-verifier/` (gitignored).
2. [`app/`](app/) is a *copy* of it, extended and committed:
   - `lib/zkwrap/groth16.ak`, `lib/zkwrap/risc0.ak` — copied verbatim.
   - `lib/zkwrap/verify.ak` — the generated policy surface, moved from
     `validators/` to `lib/` so the app validator can import it (the sample
     `validator wrapper` block is dropped; its composed tests now call
     `verify` directly).
   - `lib/steel/journal.ak` — **new**: the journal decoder.
   - `validators/steel_app.ak` — **new**: the app validator + policy.
3. On regeneration (new guest → new `image_id`, or a new trusted setup):
   re-run the pipeline, re-copy the `lib/zkwrap/` modules and the constants
   block of `verify.ak`, leave the app-owned files alone. The app only touches
   the stable `pub fn verify(...)` surface and slices `journal_bytes` itself.

## Trust-anchor caveat

On Ethereum, Steel commitments are validated against the `blockhash` opcode or
the EIP-4788 beacon-roots contract — the chain itself anchors the proof.
**Cardano has no view of Ethereum block hashes.** The proof soundly shows *"the
account held this balance in the state committed to by block hash B"*; who
vouches that B is a real, canonical, final Ethereum block is **out of scope
here** — the demo pins B in the datum, i.e. whoever creates the UTxO chooses
the anchor. To close this gap: a wrapped consensus proof
(SP1-Helios) is needed attesting that B is finalized, checked in the same transaction.
It could also be build with SP1-Helios and verified on Caradno using zkwrap toolkit.

## Prerequisites

Same as [`examples/risc0-aiken-groth16`](../risc0-aiken-groth16/README.md)
(RISC Zero toolchain, Docker, Go, aiken, the outer trusted setup), plus a
Sepolia RPC endpoint that serves `eth_getProof` — the free
`https://ethereum-sepolia-rpc.publicnode.com` works.

## Run it

From the repo root:

```bash
# 1. Build the gnark outer prover (once).
( cd zkwrap-gnark && go build -o /tmp/zkwrap-gnark ./cmd/zkwrap-gnark )
export ZKWRAP_GNARK_BIN=/tmp/zkwrap-gnark

# 2. Outer trusted setup (one-time, ~1 GB proving key; see the base example).
export ZKWRAP_SETUP_DIR="$HOME/zkwrap-setup"

# 3. Run the live pipeline: preflight → prove → wrap → generate → aiken check.
#    On WSL, keep the cargo target dir on native ext4 (not /mnt/*) — far faster,
#    and C-heavy dependency builds are unreliable on the 9p mount.
export CARGO_TARGET_DIR="$HOME/.cache/zkwrap-steel-target"
export ETH_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
cd examples/risc0-steel-erc20
cargo run --release

# 4. Check the app project (uses the committed fixture proof).
cd app && aiken check
```

`STEEL_TOKEN` / `STEEL_ACCOUNT` override the queried token/holder (defaults are
the upstream Steel example's Sepolia test-USDT + a known holder). Changing them
changes the journal, so the committed `app/` fixtures only match the defaults —
a fresh run against other values regenerates `generated/steel-verifier/` with
fresh fixtures to re-copy.

Note that a re-run reads *current* Sepolia state: the fixture constants in
`app/` (block digest, balance) come from the specific block the committed run
observed; a new run pins a new block.