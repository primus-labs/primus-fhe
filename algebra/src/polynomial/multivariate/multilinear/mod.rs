mod dense;

pub use dense::DenseMultilinearExtension;

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Index, Neg, Sub, SubAssign};

use num_traits::Zero;

use super::PolynomialTrait;
use crate::Field;

/// This trait describes an interface for the multilinear extension
/// of an array.
/// The latter is a multilinear polynomial represented in terms of its
/// evaluations over the domain {0,1}^`num_vars` (i.e. the Boolean hypercube).
///
/// Index represents a point, which is a vector in {0,1}^`num_vars` in little
/// endian form. For example, `0b1011` represents `P(1,1,0,1)`
pub trait MultilinearExtension<F: Field>:
    Sized
    + Clone
    + Debug
    + Zero
    + Index<usize>
    + Add
    + Neg
    + Sub
    + AddAssign
    + SubAssign
    + for<'a> AddAssign<&'a Self>
    + for<'a> AddAssign<(F, &'a Self)>
    + for<'a> SubAssign<&'a Self>
    + PolynomialTrait<F, Point = Vec<F>>
{
    /// Return the number of variables in `self`
    fn num_vars(&self) -> usize;

    /// Outputs an `l`-variate multilinear extension where value of evaluations
    /// are sampled at random.
    fn rand<R: rand::Rng + rand::CryptoRng>(num_vars: usize, rng: &mut R) -> Self;

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    fn fix_variables(&self, partial_point: &[F]) -> Self;

    /// Return a list of evaluations over the domain, which is the boolean
    /// hypercube. The evaluations are in little-endian order.
    fn to_evaluations(&self) -> Vec<F>;
}
