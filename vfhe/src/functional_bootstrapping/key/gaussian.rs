use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use algebra::{field::NTTField, ring::Ring};
use lattice::RGSW;
use num_traits::cast;

use super::FunctionalBootstrappingKey;

/// FHEW gaussian bootstrapping key
pub struct FHEWGaussianBootstrappingKey<F: NTTField> {
    data: Vec<Vec<RGSW<F>>>,
    basis: usize,
    degree: u32,
    max: usize,
}

impl<F: NTTField, I: SliceIndex<[Vec<RGSW<F>>]>> IndexMut<I> for FHEWGaussianBootstrappingKey<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: NTTField, I: SliceIndex<[Vec<RGSW<F>>]>> Index<I> for FHEWGaussianBootstrappingKey<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: NTTField> FHEWGaussianBootstrappingKey<F> {
    /// Creates a new [`FHEWGaussianBootstrappingKey<F>`].
    #[inline]
    pub fn new(data: Vec<Vec<RGSW<F>>>, basis: usize, degree: u32) -> Self {
        Self {
            data,
            basis,
            degree,
            max: basis.pow(degree),
        }
    }

    /// Returns the basis of this [`FHEWGaussianBootstrappingKey<F>`].
    #[inline]
    pub fn basis(&self) -> usize {
        self.basis
    }

    /// Returns the degree of this [`FHEWGaussianBootstrappingKey<F>`].
    #[inline]
    pub fn degree(&self) -> u32 {
        self.degree
    }

    /// Returns the max of this [`FHEWGaussianBootstrappingKey<F>`].
    #[inline]
    pub fn max(&self) -> usize {
        self.max
    }
}

impl<F: NTTField> FunctionalBootstrappingKey for FHEWGaussianBootstrappingKey<F> {
    type ACC = RGSW<F>;

    type Key = Vec<RGSW<F>>;

    #[inline]
    fn iter(&self) -> std::slice::Iter<Self::Key> {
        self.data.iter()
    }

    fn functional_bootstrapping_iter<R: Ring>(
        _acc: Self::ACC,
        _a_i: R,
        _s_i: &Self::Key,
        _n_rlwe: usize,
        _n_rlwe_mul_2_div_q_lwe: usize,
    ) -> Self::ACC {
        unimplemented!()
    }

    #[inline]
    fn functional_bootstrapping<R: Ring>(
        &self,
        acc: Self::ACC,
        a: &[R],
        _n_rlwe: usize,
        _n_rlwe_mul_2_div_q_lwe: usize,
    ) -> Self::ACC {
        let r_m = cast::<<R as Ring>::Inner, usize>(R::modulus()).unwrap();
        assert!(r_m <= self.max);

        let multiple = 1usize << (self.max.trailing_zeros() - r_m.trailing_zeros());

        let basis = self.basis();

        self.iter().zip(a).fold(acc, |mut acc, (s_i, &a_i)| {
            let decompose = a_i.decompose(basis);

            for (j, a_i_j) in decompose.into_iter().enumerate() {
                acc = acc.mul_with_rgsw(&s_i[j * basis + a_i_j.cast_into_usize() * multiple]);
            }
            acc
        })
    }
}
