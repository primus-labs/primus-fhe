//! Modular arithmetic traits and prepared modulus switching.
//!
//! This crate defines the algebraic interface between modulus types
//! (implemented in `primus_modulus`) and values.  Each arithmetic
//! operation — reduce, add, sub, mul, square, neg, exp, dot-product,
//! inverse, division — has its own fine-grained trait so that modulus
//! types only need to implement the subset they actually support.
//!
//! The two marker supertraits [`RingContext`] and [`FieldContext`]
//! aggregate the full ring / field operation sets respectively.
//! [`RingContext`] also includes bounded signed encoding via [`EncodeSigned`],
//! mixed signed dot products via [`ReduceDotProductSigned`], and preparation
//! via [`PrepareModulusSwitch`]. The concrete [`ModulusSwitch`] executes fixed
//! source/target conversions without depending on a particular modulus type.
//! These names describe supported operation sets rather than proving algebraic
//! properties: in particular, [`FieldContext`] does not guarantee that the
//! modulus is prime or that every nonzero residue is invertible.
//!
//! # Implementing [`RingContext`] / [`FieldContext`]
//!
//! Both are *marker* traits with blanket impls: implement every listed
//! `Reduce*` trait, [`EncodeSigned`] and [`PrepareModulusSwitch`] for your modulus
//! type to obtain [`RingContext`]. Implement [`ExplicitModulus`] and the additional
//! `LazyReduce*` / field traits to obtain [`FieldContext`]. Callers remain
//! responsible for validating any required primality or invertibility assumptions.

#![deny(missing_docs)]

mod common;
mod error;

mod lazy_ops;
mod lazy_slice_ops;
mod modulus_switch;
mod ops;
mod signed;
mod slice_ops;

pub mod prelude;

pub use common::{FieldContext, RingContext};
pub use error::ReduceError;
pub use lazy_ops::*;
pub use lazy_slice_ops::*;
pub use modulus_switch::{ModulusSwitch, PrepareModulusSwitch};
pub use ops::*;
pub use signed::{EncodeSigned, ReduceDotProductSigned};
pub use slice_ops::*;

use num_traits::ConstZero;
use primus_integer::FheUint;
use rand::distr::Uniform;

/// Trait for types that represent a modulus.
pub trait Modulus: Copy + core::fmt::Debug + Eq + Send + Sync {
    /// The scalar type that values are reduced into (e.g. `u64`).
    type ValueT: FheUint;

    /// Returns the explicit modulus value, or `None` when the modulus is implicit
    /// (e.g. a native power-of-two modulus where the value is `2^BITS` and
    /// cannot be represented in `ValueT`).
    #[must_use]
    fn explicit_value(self) -> Option<Self::ValueT>;

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
    /// May panic if `self` does not satisfy the concrete implementation's
    /// modulus invariant. For a valid modulus, the constructed range
    /// `[0, minus_one()]` is non-empty.
    #[must_use]
    #[inline]
    fn uniform_distribution(self) -> Uniform<Self::ValueT> {
        Uniform::new_inclusive(<Self::ValueT as ConstZero>::ZERO, self.minus_one())
            .expect("uniform_distribution: invalid modulus range")
    }
}

/// Trait for moduli whose value can be represented in [`Modulus::ValueT`].
pub trait ExplicitModulus: Modulus {
    /// Returns the modulus value.
    #[must_use]
    fn value(self) -> Self::ValueT;
}
