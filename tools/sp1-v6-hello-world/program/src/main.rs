#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let a = sp1_zkvm::io::read::<u64>();
    let b = sp1_zkvm::io::read::<u64>();
    if a == 1 || b == 1 {
        panic!("trivial factors");
    }
    let product = a.checked_mul(b).expect("integer overflow");
    sp1_zkvm::io::commit(&product);
}
