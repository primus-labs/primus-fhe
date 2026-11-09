//! Single-modulus GLWE operations.
//!
//! Default features are empty: parameters, coefficient ciphertexts and signed
//! secret keys remain available without a transform backend. `ntt` / `fourier`
//! enable the corresponding keys, encryption/evaluation APIs and workspaces.
//! `fourier` is generic over an FFT table; `rustfft` / `tfhe-fft` also enable
//! `fourier` and select a concrete engine. These features can be combined.
//! `fourier` also enables the internal auxiliary NTT/CRT dependency for exact
//! coefficient key generation; it does not enable the NTT GLWE API.
//! `split-trace` adds Split35 Fourier trace keys.
//! `simd` propagates to active arithmetic dependencies without enabling a backend.
//!
//! Message operations use `encrypt_message[_to]` / `decrypt_message[_to]` and
//! ordinary parameters. Encryption explicitly selects
//! [`primus_encoding::PlaintextEmbedding`]. `encrypt_encoded_to` / `encrypt_zeros_to`
//! need only codec-free encryption parameters; `decrypt_phase_to` extracts the
//! noisy coefficient phase without decoding. Message adapters encode in place
//! into the body or existing coefficient scratch, sharing the raw numerical cores.
//!
//! For diagnostics, compare the phase against the expected message's encoding
//! with [`primus_encoding::phase_error_magnitude_slice_to`], keeping the reference
//! independent of the decoded result.

#![deny(missing_docs)]

mod automorphism;
mod ciphertext;
mod key_switch;
#[cfg(any(feature = "ntt", feature = "fourier"))]
mod packing_key_switch;
mod parameter;
#[cfg(feature = "ntt")]
mod public_key;
mod scheme_switch;
mod secret_key;
#[cfg(any(feature = "ntt", feature = "fourier"))]
mod trace;

#[cfg(any(feature = "ntt", feature = "fourier"))]
use primus_encoding::PlaintextEmbedding;
use primus_encoding::ScaledCodec;

#[cfg(feature = "fourier")]
pub use automorphism::{FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace};
#[cfg(feature = "ntt")]
pub use automorphism::{NttGlweAutomorphismKey, NttGlweAutomorphismWorkspace};
#[cfg(feature = "fourier")]
pub use ciphertext::{FourierGgswCiphertext, FourierGlevCiphertext, FourierGlweCiphertext};
pub use ciphertext::{GlevCiphertext, GlweCiphertext};
#[cfg(feature = "ntt")]
pub use ciphertext::{NttGgswCiphertext, NttGlevCiphertext, NttGlweCiphertext};
#[cfg(feature = "fourier")]
pub use key_switch::{FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace};
#[cfg(feature = "ntt")]
pub use key_switch::{NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace};
#[cfg(feature = "fourier")]
pub use packing_key_switch::FourierLwePackingKeySwitchingKey;
#[cfg(feature = "ntt")]
pub use packing_key_switch::NttLwePackingKeySwitchingKey;
pub use parameter::{
    GadgetSize, GgswParameters, GlevParameterError, GlevParameters, GlweEncryptionParameters,
    GlweKeySwitchingParameters, GlweParameterError, GlweParameters, GlweSize, GlweSizeError,
};
pub use primus_distr::{BlockOccupancy, SecretKeyDistr};
pub use primus_lattice::{GlweDimension, GlweDimensionError, LweDimension};
#[cfg(feature = "ntt")]
pub use public_key::{NttGlwePublicEncryptWorkspace, NttGlwePublicKey};
#[cfg(feature = "fourier")]
pub use scheme_switch::FourierGlweSchemeSwitchKey;
#[cfg(feature = "ntt")]
pub use scheme_switch::NttGlweSchemeSwitchKey;
pub use secret_key::GlweSecretKey;
#[cfg(feature = "fourier")]
pub use secret_key::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptor, FourierGlweEncryptorError,
    FourierGlweSecretKey,
};
#[cfg(feature = "ntt")]
pub use secret_key::{NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};
#[cfg(feature = "fourier")]
pub use trace::{FourierGlwePackingWorkspace, FourierGlweTraceKey, FourierGlweTraceWorkspace};
#[cfg(feature = "ntt")]
pub use trace::{NttGlwePackingWorkspace, NttGlweTraceKey, NttGlweTraceWorkspace};
#[cfg(feature = "split-trace")]
pub use trace::{SplitFourierGlweTraceKey, SplitFourierGlweTraceWorkspace};
