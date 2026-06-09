pub mod codegen;
pub use codegen::composer::{compose, ComposeRequest, GeneratedProject, TestBlock};
pub use codegen::{CodegenError, InnerCodegen, InnerWiring, OuterCodegen, OuterWiring, RawParam};

pub mod outer_backends;
pub use outer_backends::gnark_groth16::artifacts::{OuterParseError, OuterProof};
pub use outer_backends::gnark_groth16::Groth16Backend;

pub mod inner;
pub use inner::{Bn254Fr, Bn254G1, Bn254G2, Bn254Proof, Bn254Vk, CanonicalInnerProof, ParseError};
