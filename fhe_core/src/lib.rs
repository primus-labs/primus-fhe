#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Implementations of FHE core operations.

mod error;

mod parameter;

mod bool_plaintext;
mod ciphertext;

mod secret_key;

pub mod utils;

pub use error::FHECoreError;

pub use parameter::{ConstParameters, DefaultFieldU32, Parameters};

pub use bool_plaintext::{decode, encode, LWEBoolMessage, LWEModulusType};
pub use ciphertext::{
    LWECiphertext, NTRUCiphertext, NTTNTRUCiphertext, NTTRLWECiphertext, RLWECiphertext,
};

pub use secret_key::{SecretKeyPack, SecretKeyType};
