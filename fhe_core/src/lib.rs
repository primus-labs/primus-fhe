#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Implementations of FHE core operations.

mod error;

mod parameter;

mod bool_plaintext;
mod ciphertext;

mod secret_key;

mod key_switch;

mod modulus_switch;
pub mod utils;

pub use error::FHECoreError;

pub use parameter::{BlindRotationType, ConstParameters, DefaultFieldU32, Parameters};

pub use bool_plaintext::{decode, encode, LWEBoolMessage, LWEModulusType};
pub use ciphertext::{
    LWECiphertext, NTRUCiphertext, NTTNTRUCiphertext, NTTRLWECiphertext, RLWECiphertext,
};

pub use secret_key::{SecretKeyPack, SecretKeyType};

pub use key_switch::KeySwitchingKey;

pub use modulus_switch::{lwe_modulus_switch, lwe_modulus_switch_inplace};
