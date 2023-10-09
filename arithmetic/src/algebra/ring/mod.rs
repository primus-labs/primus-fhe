use super::group::{AdditiveAbelianGroup, MultiplicativeMonoid};
use super::MulCommutativity;

/// Ring
pub trait Ring: AdditiveAbelianGroup + MultiplicativeMonoid {}

impl<R> Ring for R where R: AdditiveAbelianGroup + MultiplicativeMonoid {}

/// Commutative Ring
pub trait CommutativeRing: Ring + MulCommutativity {}

impl<R> CommutativeRing for R where R: Ring + MulCommutativity {}
