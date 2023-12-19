#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This library contains an implementation of a fully homomorphic encryption scheme.

mod parameter;
mod scheme;

mod ciphertext;
mod plaintext;

mod publickey;
mod secretkey;

mod functional_bootstrapping;

pub use parameter::{LWEParam, RLWEParam};
pub use scheme::Vfhe;

pub use ciphertext::{LWECiphertext, RLWECiphertext};
pub use plaintext::{LWEPlaintext, RLWEPlaintext};

pub use publickey::{LWEPublicKey, RLWEPublicKey};
pub use secretkey::{LWESecretKey, LWESecretKeyDistribution, RLWESecretKey};

pub use functional_bootstrapping::{
    FHEWGaussianBootstrappingKey, FunctionalBootstrappingKey, TFHEBinaryBootStrappingKey,
    TFHETernaryBootStrappingKey,
};
