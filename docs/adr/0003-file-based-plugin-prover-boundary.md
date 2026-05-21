# File-based boundary between plugin and prover binary

The canonical inner proof (inner VK, proof bytes, public inputs, `n_real`) is exchanged between the Rust plugin library and the outer backend prover binary as files on disk, not via in-memory structs, CGO FFI, or a shared language runtime.

CGO was considered (following SP1's `native-gnark` approach) and rejected for our case: unlike SP1, we are not embedding gnark proving into the host's build pipeline — the plugin and the prover are independent components that can be installed and versioned separately. File-based IPC keeps both sides free to evolve independently, lets each component be written in its native language (Rust for plugins, Go for gnark, Rust for future Halo2), and avoids requiring Go toolchain presence at Rust build time.

The canonical format spec lives in `docs/schemas/` and is the contract. Both sides implement their side of it in their respective languages.
