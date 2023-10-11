#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// #![doc = include_str!("../README.md")]

pub mod algebra;
pub mod modulo;
pub mod number_theory;

pub mod error;

pub mod constants;

mod primitive;
pub(crate) use primitive::Widening;
