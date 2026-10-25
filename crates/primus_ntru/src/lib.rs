//! Secret-key NTRU encryption over `Z_q[X] / (X^N + 1)`.
//!
//! The scalar ciphertext invariant is
//! `c = f^(-1) * (e + Delta * m)`.  Coefficient-domain parameters and
//! secret keys are shared by the exact NTT and native-torus Fourier backends.
//!
//! Message encryption provides `encrypt_message` / `encrypt_message_to` with explicit
//! [`primus_encoding::PlaintextEmbedding`]. Raw encryption provides
//! `encrypt_encoded_to` and `encrypt_zeros` / `encrypt_zeros_to`. The `_to` methods
//! reuse output storage; Fourier operations also reuse an encryption workspace.
//! `decrypt_phase_to` returns undecoded coefficients: NTT takes a modulus and
//! table, while Fourier takes an FFT engine and decryption workspace.
//! `decrypt_message` / `decrypt_message_to` additionally take [`NtruParameters`]
//! for the plaintext codec. Both embeddings use the same decoder. Diagnostics
//! compare the phase with the expected message's encoding using
//! [`primus_encoding::phase_error_magnitude_slice_to`].
//! Key generation and encoded/zero encryption take [`NtruEncryptionParameters`],
//! the codec-free ring/sampling state shared by ordinary and [`NlevParameters`].
//!
//! `encrypt_nlev_constant_to` encrypts raw ring constants without plaintext
//! scaling. In particular, `NLev[1]` maps a coefficient polynomial to an encrypted
//! NTRU accumulator through an external product. This differs from `NGSW[1]`,
//! which multiplies a ciphertext already encrypted under the same key.
//!
//! `encrypt_ngsw_signed_constant_batch_to` accepts signed coefficient-secret
//! slices directly and writes consecutive NGSWs after checking the batch once.
//! NTT requires magnitudes below `q`, and needs no message scratch or transform
//! because constants evaluate identically at every NTT point. Fourier accepts
//! all signed values, reuses a gadget workspace and preserves per-level native-ring
//! scaling followed by the FFT. Empty batches consume no randomness.
//!
//! Explicit-modulus conversions use bounded signed encoding: every secret
//! coefficient must have unsigned magnitude strictly less than the target
//! ciphertext modulus. [`NtruEncryptionParameters`] checks this for its sampling support.
//! Callers importing coefficient keys or selecting a different target modulus
//! must establish the same bound; conversion does not perform general reduction.
//! The native Fourier representation accepts every signed coefficient.

//! [`NtruLweKeySwitchingKey`] converts coefficient NTRU at Q to an independent
//! LWE secret at q, reusing exact modulus rounding, sample extraction and LWE
//! key switching. [`LweReturnEvaluator`] binds the key and target q. Prepare
//! [`NtruLweKeySwitchingWorkspace`] for single coefficients or
//! [`LweReturnBatchWorkspace`] for shared-input prefixes and different-input streams.
//! The latter tracks the current stream's valid prefix, so stale slots are not submitted.
//! Arbitrary or repeated indices remain available through
//! [`LweReturnEvaluator::return_many_at_to`].
//! Source and target use the same coefficient type; no FFT/NTT table is needed.
//!
//! Same-secret automorphism, trace/reverse trace, coefficient projection and
//! expansion use separate NTT/Fourier keys and reusable coefficient workspaces.
//! `NttNtruSchemeSwitchKey` / `FourierNtruSchemeSwitchKey` convert coefficient
//! NLev to transformed NGSW with independent key/output bases. Their
//! secret-dependent-key and f/f²-weighted noise contracts require additional
//! analysis when used for CBS in the NTRU TFHE backends.
//!
//! # Features
//!
//! Default features are empty: coefficient types, parameters, signed secrets and
//! the NTRU-to-LWE return path need no transform backend. `ntt` / `fourier` enable
//! the corresponding keys, encryption/evaluation APIs and workspaces. `fourier`
//! is generic over an FFT table; `rustfft` / `tfhe-fft` also enable `fourier` and
//! select a concrete engine. These features can be combined. `simd` propagates
//! to active arithmetic dependencies without enabling a backend.

#![deny(missing_docs)]

mod automorphism;
mod ciphertext;
mod fourier_precision;
pub use fourier_precision::FourierPrecision;
mod error;
mod key_switch;
mod parameter;
mod scheme_switch;
mod secret_key;
#[cfg(feature = "fourier")]
pub mod split;
#[cfg(any(feature = "ntt", feature = "fourier"))]
mod trace;

#[cfg(feature = "fourier")]
pub use automorphism::{FourierNtruAutomorphismKey, FourierNtruAutomorphismWorkspace};
#[cfg(feature = "ntt")]
pub use automorphism::{NttNtruAutomorphismKey, NttNtruAutomorphismWorkspace};
#[cfg(feature = "fourier")]
pub use ciphertext::{FourierNgswCiphertext, FourierNlevCiphertext, FourierNtruCiphertext};
pub use ciphertext::{NgswCiphertext, NlevCiphertext, NtruCiphertext};
#[cfg(feature = "ntt")]
pub use ciphertext::{NttNgswCiphertext, NttNlevCiphertext, NttNtruCiphertext};
pub use error::NtruError;
#[cfg(feature = "fourier")]
pub use key_switch::FourierNtruKeySwitchingKey;
#[cfg(feature = "ntt")]
pub use key_switch::NttNtruKeySwitchingKey;
pub use key_switch::{
    LweReturnBatchWorkspace, LweReturnEvaluator, NtruLweKeySwitchingKey,
    NtruLweKeySwitchingWorkspace,
};
pub use parameter::{
    NlevParameterError, NlevParameters, NtruEncryptionParameters, NtruParameterError,
    NtruParameters,
};
pub use primus_distr::SecretKeyDistr;
pub use primus_lattice::LweDimension;
#[cfg(feature = "fourier")]
pub use primus_lattice::workspace::{
    FourierNtruCmuxWorkspace, FourierNtruExternalProductWorkspace, FourierNtruSplitWorkspace,
};
#[cfg(feature = "ntt")]
pub use primus_lattice::workspace::{NttNtruCmuxWorkspace, NttNtruExternalProductWorkspace};
#[cfg(feature = "fourier")]
pub use scheme_switch::FourierNtruSchemeSwitchKey;
pub use scheme_switch::NtruProjectionMethod;
#[cfg(feature = "ntt")]
pub use scheme_switch::{NttNtruProjectionKey, NttNtruSchemeSwitchKey};
pub use secret_key::NtruSecretKey;
#[cfg(feature = "fourier")]
pub use secret_key::{
    FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSecretKey,
};
#[cfg(feature = "ntt")]
pub use secret_key::{NttNtruGadgetEncryptWorkspace, NttNtruSecretKey};
#[cfg(feature = "fourier")]
pub use trace::{FourierNtruTraceKey, FourierNtruTraceWorkspace};
#[cfg(feature = "ntt")]
pub use trace::{NttNtruTraceKey, NttNtruTraceWorkspace};

#[cfg(feature = "fourier")]
pub use primus_lattice::ntru::{FourierNtruSplitAutomorphism, FourierNtruSplitGadget};
