#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This crate defines the core structures and algorithms for fully homomorphic encryption.

mod error;

mod parameter;

mod public_key;
mod secret_key;

mod ciphertext;
mod plaintext;

mod blind_rotation;
mod key_switch;

mod automorphism;
mod trace;

mod modulus_switch;

pub mod utils;

pub use error::FHECoreError;

pub use parameter::{GadgetRlweParameters, KeySwitchingParameters, LweParameters, RlweParameters};

pub use public_key::{LwePublicKey, LwePublicKeyRlweMode, NttRlwePublicKey};
pub use secret_key::{
    LweSecretKey, LweSecretKeyType, NttRlweSecretKey, RingSecretKeyType, RlweSecretKey,
};

pub use ciphertext::{CmLweCiphertext, LweCiphertext, NttRlweCiphertext, RlweCiphertext};
pub use plaintext::{decode, encode};

pub use blind_rotation::{BinaryBlindRotationKey, BlindRotationKey, TernaryBlindRotationKey};
pub use key_switch::*;

pub use automorphism::{AutoKey, AutoSpace};
pub use trace::TraceKey;

pub use modulus_switch::{
    lwe_modulus_switch, lwe_modulus_switch_assign, lwe_modulus_switch_inplace,
};
