#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

//! A linearly homomorphic version of BFV.

mod ciphertext;
mod context;
mod plaintext;
mod publickey;
mod scheme;
mod secretkey;

pub use ciphertext::{BFVCiphertext, CipherField, DIMENSION_N};
pub use context::BFVContext;
pub use plaintext::{BFVPlaintext, PlainField};
pub use publickey::BFVPublicKey;
pub use scheme::BFVScheme;
pub use secretkey::BFVSecretKey;
