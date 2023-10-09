#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// #![doc = include_str!("../README.md")]

pub mod algebra;
pub mod modulo;
pub mod number_theory;

mod primitive;
pub mod slice;

pub mod constants;

pub(crate) use primitive::BigIntHelperMethods;
