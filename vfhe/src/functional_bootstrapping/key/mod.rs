use std::slice::Iter;

use algebra::ring::Ring;

mod binary;
mod gaussian;
mod ternary;

pub use binary::TFHEBinaryBootStrappingKey;
pub use gaussian::FHEWGaussianBootstrappingKey;
pub use ternary::TFHETernaryBootStrappingKey;

/// The trait to use the bootstrapping key
pub trait FunctionalBootstrappingKey {
    /// accomulator
    type ACC;

    /// inner key type
    type Key;

    /// iter inner key
    fn iter(&self) -> Iter<Self::Key>;

    /// inner single functional bootstrapping step
    fn functional_bootstrapping_iter<R: Ring>(
        acc: Self::ACC,
        a_i: R,
        s_i: &Self::Key,
        n_rlwe: usize,
        n_rlwe_mul_2_div_q_lwe: usize,
    ) -> Self::ACC;

    /// functional bootstrapping
    #[inline]
    fn functional_bootstrapping<R: Ring>(
        &self,
        acc: Self::ACC,
        a: &[R],
        n_rlwe: usize,
        n_rlwe_mul_2_div_q_lwe: usize,
    ) -> Self::ACC {
        self.iter().zip(a).fold(acc, |acc, (s_i, &a_i)| {
            Self::functional_bootstrapping_iter(acc, a_i, s_i, n_rlwe, n_rlwe_mul_2_div_q_lwe)
        })
    }
}
