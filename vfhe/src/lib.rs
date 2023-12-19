#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This library contains an implementation of a fully homomorphic encryption scheme.

mod params;
mod scheme;

mod cipher;
mod plain;

mod pubkey;
mod seckey;

mod functional_bootstrapping;

pub use params::{LWEParam, RLWEParam};
pub use scheme::Vfhe;

pub use cipher::{LWECiphertext, RLWECiphertext};
pub use plain::{LWEPlaintext, RLWEPlaintext};

pub use pubkey::{LWEPublicKey, RLWEPublicKey};
pub use seckey::{LWESecretKey, LWESecretKeyDistribution, RLWESecretKey};

pub use functional_bootstrapping::{
    FHEWGaussianBootstrappingKey, TFHEBinaryBootStrappingKey, TFHETernaryBootStrappingKey,
};
