//! Value-side modular arithmetic traits.
//!
//! This crate is the mirror of [`primus_reduce`]: where `primus_reduce`
//! attaches operations to the *modulus* (`modulus.reduce_add(a, b)`),
//! this crate attaches them to the *value* (`a.add_modulo(b, modulus)`).
//! Each trait is implemented via a blanket impl that delegates to the
//! corresponding [`primus_reduce`] trait, simply reversing the call order.
//!
//! The naming convention is `XxxModulo` (value-side) ↔ `ReduceXxx` (modulus-side).

#![deny(missing_docs)]

mod lazy_ops;
mod lazy_slice_ops;
mod ops;
mod slice_ops;

pub mod prelude;

pub use lazy_ops::*;
pub use lazy_slice_ops::*;
pub use ops::*;
pub use slice_ops::*;
