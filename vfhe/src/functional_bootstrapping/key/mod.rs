use std::slice::Iter;

use algebra::{field::NTTField, ring::Ring};

// mod binary;
mod gaussian;
// mod ternary;

// pub use binary::TFHEBinaryBootStrappingKey;
pub use gaussian::FHEWGaussianBootstrappingKey;
use lattice::{RGSW, RLWE};
// pub use ternary::TFHETernaryBootStrappingKey;

/// bootstrapping key
#[derive(Debug, Clone)]
pub enum BootstrappingKey<F: NTTField> {
    /// TFHE binary bootstrapping key
    TFHEBinary(Vec<RGSW<F>>),
    /// TFHE ternary bootstrapping key
    TFHETernary(Vec<(RGSW<F>, RGSW<F>)>),
}

impl<F: NTTField> BootstrappingKey<F> {
    ///
    #[inline]
    pub fn binary_bootstrapping_key(key: Vec<RGSW<F>>) -> Self {
        Self::TFHEBinary(key)
    }

    ///
    #[inline]
    pub fn ternary_bootstrapping_key(key: Vec<(RGSW<F>, RGSW<F>)>) -> Self {
        Self::TFHETernary(key)
    }

    ///
    pub fn bootstrapping<R: Ring>(&self, acc: RLWE<F>, a: &[R], l: usize, l2dq: usize) -> RLWE<F> {
        match self {
            BootstrappingKey::TFHEBinary(bk) => bk.iter().zip(a).fold(acc, |acc, (s_i, &a_i)| {
                let median = s_i
                    .mul_with_rlwe(&acc)
                    .mul_with_monic_monomial_sub1(l, l2dq, -a_i);
                acc.add_element_wise(&median)
            }),
            BootstrappingKey::TFHETernary(bk) => {
                bk.iter().zip(a).fold(acc, |acc, (s_i, &a_i)| {
                    // u = 1
                    let median = s_i
                        .0
                        .mul_with_rlwe(&acc)
                        .mul_with_monic_monomial_sub1(l, l2dq, -a_i);
                    let acc = acc.add_element_wise(&median);

                    // u = -1
                    let median = s_i
                        .1
                        .mul_with_rlwe(&acc)
                        .mul_with_monic_monomial_sub1(l, l2dq, a_i);
                    acc.add_element_wise(&median)
                })
            }
        }
    }
}

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
