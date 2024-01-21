#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Cryptography crate for Lattice-based Encryption Schemes
//!
//! This crate provides the foundational structures for implementing lattice-based cryptography,
//! specifically focusing on Learning with Errors (LWE) and Ring Learning with Errors (RLWE) schemes.
//! It includes constructs for working with polynomials and Number Theoretic Transforms (NTT)
//! which are essential for efficient operations in these cryptographic systems.
//!
//! Structures provided in this crate:
//! - `LWE`: Represents the Learning with Errors structure, a basic building block for lattice-based
//!   cryptography, allowing operations on vectors with error terms.
//! - `RLWE`: Extends the LWE concept to rings, enabling more efficient cryptographic transformations
//!   and operations through polynomial representations.
//! - `GadgetRLWE`: A variant of RLWE that facilitates the use of different bases, aimed at reducing
//!   noise growth during multiplication with polynomials. This is particularly useful in homomorphic
//!   encryption where maintaining low noise is critical for decryption accuracy.
//! - `RGSW`: Implements the Ring GSW scheme. RGSW is a homomorphic encryption scheme that enables
//!   computations on encrypted data, representing a key component in advanced encryption systems like
//!   fully homomorphic encryption (FHE).
//!
//! Usage of the crate's structures allows for the construction of secure cryptographic protocols and
//! can be the foundation for more complex operations such as encrypted data manipulation and secure
//! computation protocols.
//!
//! Note: This crate assumes familiarity with lattice-based cryptography. The structures herein are
//! low-level components that are to be used as part of a larger cryptographic protocol. Proper
//! initialization, key management, and security considerations are beyond the scope of this crate
//! and must be carefully implemented by the user.

mod gadget;
mod lwe;
mod rgsw;
mod rlwe;
mod utils;

pub use gadget::{GadgetRLWE, NTTGadgetRLWE};
pub use lwe::{NewLWE, LWE};
pub use rgsw::{NTTRGSW, RGSW};
pub use rlwe::{NTTRLWE, RLWE};
pub use utils::*;
