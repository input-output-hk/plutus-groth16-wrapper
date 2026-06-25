fn main() {
    // Recompiles the guest ELF when the SP1 toolchain is present. Set
    // SP1_SKIP_PROGRAM_BUILD=true to skip and use the committed
    // program/elf/riscv32im-succinct-zkvm-elf (e.g. when host and SP1 toolchain
    // Rust versions differ).
    sp1_build::build_program("program");
}
