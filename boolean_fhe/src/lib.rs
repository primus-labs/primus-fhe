#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! Boolean FHE is a library for homomorphic encryption of boolean values.

mod parameter;

mod evaluate;
mod lut;

mod decrypt;
mod encrypt;
mod key_gen;
mod secret_key;

pub use parameter::*;

pub use evaluate::{Evaluator, KeySwitchingKey};
pub use lut::LookUpTable;

pub use decrypt::Decryptor;
pub use encrypt::Encryptor;
pub use key_gen::KeyGen;
pub use secret_key::SecretKeyPack;
