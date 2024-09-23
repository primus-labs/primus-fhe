// It is derived from https://github.com/arkworks-rs/sumcheck.
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Index, Neg, Sub, SubAssign};

use num_traits::Zero;

use crate::Field;

mod dense;
mod sparse;

pub use dense::DenseMultilinearExtension;
pub use sparse::SparsePolynomial;

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
{
    /// The type of evaluation points for this polynomial.
    type Point: ?Sized + Debug;

    /// Return the number of variables in `self`
    fn num_vars(&self) -> usize;

    /// Evaluates `self` at the given `point` in `Self::Point`.
    fn evaluate(&self, point: &Self::Point) -> F;

    /// Outputs an `l`-variate multilinear extension where value of evaluations
    /// are sampled at random.
    fn random<R: rand::Rng + rand::CryptoRng>(num_vars: usize, rng: &mut R) -> Self;

    /// Reduce the number of variables of `self` by fixing the
    /// `partial_point.len()` variables at `partial_point`.
    fn fix_variables(&self, partial_point: &[F]) -> Self;

    /// Return a list of evaluations over the domain, which is the boolean
    /// hypercube. The evaluations are in little-endian order.
    fn to_evaluations(&self) -> Vec<F>;
}

const PAR_NUM_VAR_THRESHOLD: usize = 20;
