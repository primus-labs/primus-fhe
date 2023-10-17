#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// #![doc = include_str!("../README.md")]

pub mod field;
pub mod modulo;
pub mod utils;

pub mod error;

pub mod polynomial;

mod primitive;
pub(crate) use primitive::Widening;
