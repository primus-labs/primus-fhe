#![deny(missing_docs)]

//! Ciphertext storage and low-level lattice arithmetic.
//!
//! # Correctness
//!
//! Ciphertext wrappers own or borrow raw storage. They do not carry a secret key,
//! polynomial size, modulus, gadget basis, or transform table, and their raw
//! constructors do not validate these properties. The caller must establish the
//! layout and mathematical contracts below before invoking an operation.
//!
//! - Buffers must contain complete ciphertexts in the documented representation.
//!   Lengths include every component, gadget level, row, and RNS modulus block.
//!   Size descriptors validate dimension arithmetic, not the buffers they describe.
//! - Arithmetic operands must have compatible keys, encodings, moduli, and layouts.
//!   Gadget operands must also agree on basis and level/row order. NTT operands
//!   must use the same transform convention and evaluation order.
//! - Values must satisfy the selected arithmetic backend's input ranges. Unless
//!   an operation explicitly permits lazy values, supply canonical residues; for
//!   the native modulus every value of the underlying unsigned type is canonical.
//! - Fourier ciphertexts use normalized torus transforms. Table, packing, and
//!   scale must agree; floating-point transforms and gadget decomposition can
//!   introduce approximation error. Noise bounds and decryptability belong to
//!   the higher-level cryptographic API.
//! - Output storage and reusable workspaces must have the exact shapes required by
//!   each operation. An overwriting operation initializes its output; an
//!   accumulating operation requires a valid initialized accumulator.
//!
//! # Panics
//!
//! This crate does not systematically check these correctness contracts. Debug
//! assertions diagnose selected violations but are not release-mode validation.
//! Slice operations and arithmetic backends may panic on malformed inputs;
//! iterator-based operations may instead omit trailing blocks or process only a
//! common prefix. Absence of a panic does not establish a valid ciphertext.
//! Method-level panic documentation identifies specific failure conditions,
//! rather than promising rejection of every invalid input.
//!
//! # Features
//!
//! Default features are empty: coefficient storage and arithmetic need no transform.
//! - `serde` enables serialization of [`lwe::Lwe`] and [`lwe::MultiMsgLwe`]
//!   when their backing storage supports it; deserialization does not validate layouts.
//! - `ntt` enables NTT ciphertexts, conversions, operations and workspaces.
//! - `fourier` enables the corresponding Fourier APIs without selecting an FFT engine.
//! - `rustfft` / `tfhe-fft` enable `fourier` and the selected FFT implementation.
//! - `rns` enables `ntt`, CRT/DCRT ciphertexts and their multiplication workspace.
//! - `simd` enables nightly SIMD in active arithmetic dependencies; it does not
//!   activate a transform backend, FFT implementation or `rns`.
//!
//! [`RnsGlweSize`] and [`RnsGadgetSize`] remain available without `rns`:
//! their layout APIs do not depend on RNS arithmetic.

#[macro_use]
mod macros;

mod dimension;
mod gadget;
mod size;

pub use dimension::{GlweDimension, GlweDimensionError, LweDimension, LweDimensionError};
pub use size::{GadgetSize, GlweSize, GlweSizeError, RnsGadgetSize, RnsGlweSize};

/// GGSW matrix ciphertexts.
pub mod ggsw;
/// GLev gadget-decomposed ciphertexts.
pub mod glev;
/// Module-LWE (GLWE) ciphertexts, with optional NTT/Fourier and CRT/DCRT representations.
pub mod glwe;
/// Standard LWE ciphertexts.
pub mod lwe;
/// GSW-style NTRU ciphertexts.
pub mod ngsw;
/// Gadget-decomposed NTRU ciphertexts.
pub mod nlev;
/// NTRU ciphertexts.
pub mod ntru;
/// Reusable workspaces and borrowed scratch views.
pub mod workspace;
