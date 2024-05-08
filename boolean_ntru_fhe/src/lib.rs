#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This library contains an implementation of a fully homomorphic encryption scheme.

mod error;

mod parameter;

mod ciphertext;
mod plaintext;

mod bootstrapping_key;
mod evaluation_key;
mod key_switching_key;
mod secret_key;

pub use error::FHEError;

pub use parameter::{
    ConstParameters, DefaultFieldTernary128, Parameters, ParametersBuilder,
    CONST_DEFAULT_TERNARY_128_BITS_PARAMERTERS, DEFAULT_TERNARY_128_BITS_PARAMERTERS,
};

pub use ciphertext::{LWECiphertext, NTRUCiphertext, NTRUModulusSwitch, NTTNTRUCiphertext};
pub use plaintext::{decode, encode, LWEMessage, LWEPlaintext};

pub use bootstrapping_key::BootstrappingKey;
pub use evaluation_key::EvaluationKey;
pub use key_switching_key::KeySwitchingKey;
pub use secret_key::{LWESecretKey, NTTRingSecretKey, RingSecretKey, SecretKeyPack, SecretKeyType};