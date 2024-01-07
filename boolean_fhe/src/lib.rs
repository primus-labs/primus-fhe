#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This library contains an implementation of a fully homomorphic encryption scheme.

mod parameter;

mod ciphertext;
mod plaintext;

mod bootstrapping_key;
mod evaluation_key;
mod key_switching_key;
mod secret_key;
mod allocator;

pub use parameter::Parameters;

pub use ciphertext::{LWECiphertext, NTTRLWECiphertext, RLWECiphertext};
pub use plaintext::LWEPlaintext;

pub use bootstrapping_key::BootstrappingKey;
pub use evaluation_key::EvaluationKey;
pub use key_switching_key::KeySwitchingKey;
pub use secret_key::{LWESecretKey, NTTRLWESecretKey, RLWESecretKey, SecretKeyPack, SecretKeyType};
