//! Prelude: re-exports all operation traits but deliberately omits
//! [`Modulus`](crate::Modulus), [`ExplicitModulus`](crate::ExplicitModulus),
//! [`FieldContext`](crate::FieldContext), [`RingContext`](crate::RingContext), and
//! [`ReduceError`](crate::ReduceError) — those must be imported explicitly when needed.
//!
//! This avoids name collisions between trait methods and inherent methods on
//! concrete modulus types.

pub use crate::lazy_ops::*;
pub use crate::lazy_slice_ops::*;
pub use crate::modulus_switch::PrepareModulusSwitch;
pub use crate::ops::*;
pub use crate::signed::{EncodeSigned, ReduceDotProductSigned};
pub use crate::slice_ops::*;
