//! Proving-engine backends. Each module here
//! implements [`OuterCodegen`](crate::codegen::OuterCodegen) for one outer
//! proving system, owning that system's artifact schema

pub mod gnark_groth16;
pub mod gnark_plonk;
