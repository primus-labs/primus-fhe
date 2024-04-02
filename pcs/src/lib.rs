//! polynomial commitment scheme

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

/// mulilinear polynomial commitment
pub mod multilinear;
/// transcript to enable Fiat-Shamir Transformation
pub mod transcript;
/// utils, mainly used to implement linear time encodable code now
pub mod utils;
