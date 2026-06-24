#![no_main]
#![no_std]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// The guest program: prove knowledge of two nontrivial factors of a number.
/// Commits the product to the journal. This is the statement the whole pipeline
/// ends up verifying on-chain.
fn main() {
    let a: u64 = env::read();
    let b: u64 = env::read();
    if a == 1 || b == 1 {
        panic!("Trivial factors")
    }
    let product = a.checked_mul(b).expect("Integer overflow");
    env::commit(&product);
}
