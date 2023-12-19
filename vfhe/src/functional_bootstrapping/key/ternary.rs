use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use algebra::{field::NTTField, ring::Ring};
use lattice::{RGSW, RLWE};

use super::FunctionalBootstrappingKey;

/// TFHE ternary bootstrapping key
pub struct TFHETernaryBootStrappingKey<F: NTTField> {
    data: Vec<(RGSW<F>, RGSW<F>)>,
}

impl<F: NTTField, I: SliceIndex<[(RGSW<F>, RGSW<F>)]>> IndexMut<I>
    for TFHETernaryBootStrappingKey<F>
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: NTTField, I: SliceIndex<[(RGSW<F>, RGSW<F>)]>> Index<I> for TFHETernaryBootStrappingKey<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: NTTField> TFHETernaryBootStrappingKey<F> {
    /// Creates a new [`TFHETernaryBootStrappingKey<F>`].
    #[inline]
    pub fn new(data: Vec<(RGSW<F>, RGSW<F>)>) -> Self {
        Self { data }
    }
}

impl<F: NTTField> FunctionalBootstrappingKey for TFHETernaryBootStrappingKey<F> {
    type ACC = RLWE<F>;

    type Key = (RGSW<F>, RGSW<F>);

    #[inline]
    fn iter(&self) -> std::slice::Iter<Self::Key> {
        self.data.iter()
    }

    fn functional_bootstrapping_iter<R: Ring>(
        acc: Self::ACC,
        a_i: R,
        s_i: &Self::Key,
        n_rlwe: usize,
        n_rlwe_mul_2_div_q_lwe: usize,
    ) -> Self::ACC {
        // u = 1
        let median = s_i.0.mul_with_rlwe(&acc).mul_with_monic_monomial_sub1(
            n_rlwe,
            n_rlwe_mul_2_div_q_lwe,
            -a_i,
        );
        let acc = acc.add_element_wise(&median);

        // u = -1
        let median = s_i.1.mul_with_rlwe(&acc).mul_with_monic_monomial_sub1(
            n_rlwe,
            n_rlwe_mul_2_div_q_lwe,
            a_i,
        );
        acc.add_element_wise(&median)
    }
}
