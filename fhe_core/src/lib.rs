#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Implementations of FHE core operations.

mod blind_rotation;
mod bool_plaintext;
mod ciphertext;
mod error;
mod key_switch;
mod modulus_switch;
mod parameter;
mod secret_key;
mod utils;

pub use blind_rotation::*;
pub use bool_plaintext::{decode, encode, LWEBoolMessage, LWEModulusType};
pub use ciphertext::{
    LWECiphertext, NTRUCiphertext, NTTNTRUCiphertext, NTTRLWECiphertext, RLWECiphertext,
};
pub use error::FHECoreError;
pub use key_switch::KeySwitchingKey;
pub use modulus_switch::lwe_modulus_switch;
pub use parameter::{ConstParameters, DefaultFieldU32, Parameters};
pub use secret_key::{NTRUSecretKeyPack, SecretKeyPack, SecretKeyType};
pub use utils::*;
