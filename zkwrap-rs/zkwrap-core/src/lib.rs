pub mod codegen;
pub use codegen::composer::{compose, ComposeRequest, GeneratedProject, TestBlock};
pub use codegen::outer_tests;
pub use codegen::{CodegenError, InnerCodegen, InnerWiring, OuterCodegen, OuterWiring, RawParam};

pub mod outer_backends;
pub use outer_backends::gnark_groth16::artifacts::{Groth16OuterProof, OuterParseError};
pub use outer_backends::gnark_groth16::Groth16Backend;
pub use outer_backends::gnark_plonk::artifacts::{PlonkOuterProof, PlonkVk};
pub use outer_backends::gnark_plonk::PlonkBackend;

pub mod outer_proof;
pub use outer_proof::{parse_outer_proof, OuterProof};

pub mod inner;
pub use inner::{
    Bn254Fr, Bn254G1, Bn254G2, Bn254Proof, Bn254Vk, CanonicalBundle, CanonicalInnerProof, Hex32,
    ParseError, ReadBundleError,
};
