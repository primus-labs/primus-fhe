#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! This library contains an implementation of a fully homomorphic encryption scheme.

mod params;
mod scheme;

mod cipher;
mod plain;

mod keygen;
mod pubkey;
mod seckey;

pub use params::{Param, Params};
pub use scheme::Vfhe;

pub use cipher::Ciphertext;
pub use plain::Plaintext;

pub use keygen::KeyGenerator;
pub use pubkey::PublicKey;
pub use seckey::SecretKey;
