//! Define the approximate signed decomposition algorithms
//! for power of 2 modulus value and non power of 2 modulus value.

mod non_pow_of_2;
mod pow_of_2;

pub use non_pow_of_2::{
    NonPowOf2ApproxSignedBasis, ScalarIter, SignedDecomposeIter, SignedOnceDecompose,
};
pub use pow_of_2::PowOf2ApproxSignedBasis;
