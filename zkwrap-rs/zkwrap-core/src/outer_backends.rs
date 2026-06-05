//! Proving-engine backends. Each module here
//! implements [`OuterBackend`](crate::codegen::OuterBackend) for one outer
//! proving system, owning that system's artifact schema

pub mod gnark_groth16;
