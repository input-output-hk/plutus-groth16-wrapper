#![no_main]

use alloy_primitives::Address;
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{
    ethereum::{EthEvmInput, ETH_SEPOLIA_CHAIN_SPEC},
    Commitment, Contract,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

sol! {
    /// ERC-20 balance function signature.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

// ABI-encodable journal: Steel's commitment (which Ethereum block the state was
// read at) plus the queried token/account and the proven balance. The token and
// account arrive as *inputs* (the guest is generic over them) but are committed
// here, so the on-chain policy can bind to them. All fields are static ABI
// types — `abi.encode` is exactly six 32-byte words, no offsets.
sol! {
    struct Journal {
        Commitment commitment;
        address token;
        address account;
        uint256 balance;
    }
}

fn main() {
    // Read the input from the host environment.
    let input: EthEvmInput = env::read();
    let token: Address = env::read();
    let account: Address = env::read();

    // Convert the input into an `EvmEnv` for execution. This checks that the
    // provided state (headers + MPT storage proofs) matches the state root of
    // the block header in the input — the soundness core of Steel.
    let evm_env = input.into_env(&ETH_SEPOLIA_CHAIN_SPEC);

    // Execute the view call against the verified state.
    let balance = Contract::new(token, &evm_env)
        .call_builder(&IERC20::balanceOfCall { account })
        .call();

    let journal = Journal {
        commitment: evm_env.into_commitment(),
        token,
        account,
        balance,
    };
    env::commit_slice(&journal.abi_encode());
}
