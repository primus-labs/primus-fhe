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

pub use parameter::{
    ConstParameters, DefaultField100, DefaultRing100, Parameters,
    CONST_DEFAULT_100_BITS_PARAMERTERS, DEFAULT_100_BITS_PARAMERTERS,
};

pub use ciphertext::{LWECiphertext, NTTRLWECiphertext, RLWECiphertext};
pub use plaintext::LWEPlaintext;

pub use bootstrapping_key::{BootstrappingKey, BootstrappingPreAllocate};
pub use evaluation_key::EvaluationKey;
pub use key_switching_key::KeySwitchingKey;
pub use secret_key::{LWESecretKey, NTTRLWESecretKey, RLWESecretKey, SecretKeyPack, SecretKeyType};
