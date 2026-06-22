//! Traits for modular reduction operations.
//!
//! This crate defines the algebraic interface between modulus types
//! (implemented in `primus_modulus`) and values.  Each arithmetic
//! operation — reduce, add, sub, mul, square, neg, exp, dot-product,
//! inverse, division — has its own fine-grained trait so that modulus
//! types only need to implement the subset they actually support.
//!
//! The two marker supertraits [`RingContext`] and [`FieldContext`]
//! aggregate the full ring / field operation sets respectively.
//!
//! # Implementing [`RingContext`] / [`FieldContext`]
//!
//! Both are *marker* traits with blanket impls: implement every listed
//! `Reduce*` (and `LazyReduce*`) trait for your modulus type and the
//! corresponding context trait is granted automatically.

#![deny(missing_docs)]

use core::fmt::Debug;

mod common;
mod error;

mod lazy_ops;
mod lazy_slice_ops;
mod ops;
mod slice_ops;

pub mod prelude;

pub use common::{FieldContext, RingContext};
pub use error::ReduceError;
pub use lazy_ops::*;
pub use lazy_slice_ops::*;
pub use ops::*;
pub use slice_ops::*;

use num_traits::ConstZero;
use primus_integer::FheUint;
use rand::distr::Uniform;

/// Trait for types that represent a modulus.
pub trait Modulus: Copy + Debug + Send + Sync {
    /// The scalar type that values are reduced into (e.g. `u64`).
    type ValueT: FheUint;

    /// Returns the modulus value, or `None` when the modulus is implicit
    /// (e.g. a native power-of-two modulus where the value is `2^BITS` and
    /// cannot be represented in `ValueT`).
    #[must_use]
    fn value(self) -> Option<Self::ValueT>;

    /// Returns the modulus value without checking that it fits in `ValueT`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the modulus value can be represented in
    /// `ValueT`, or must be prepared to handle any implementation-defined
    /// sentinel value (such as `0`) returned for implicit moduli.
    #[must_use]
    unsafe fn value_unchecked(self) -> Self::ValueT;

    /// Returns the value of the modulus minus one.
    ///
    /// Well-defined for both explicit and implicit moduli: for the implicit
    /// native power-of-two case this is `T::MAX`.
    #[must_use]
    fn minus_one(self) -> Self::ValueT;

    /// Returns a [`Uniform`] distribution over the values of [`Modulus`].
    ///
    /// # Panics
    ///
    /// Never panics for unsigned [`Modulus`] impls: the constructed range
    /// `[0, minus_one()]` is always non-empty.
    #[must_use]
    #[inline]
    fn uniform_distribution(self) -> Uniform<Self::ValueT> {
        Uniform::new_inclusive(<Self::ValueT as ConstZero>::ZERO, self.minus_one())
            .expect("uniform_distribution: invalid modulus range")
    }
}
