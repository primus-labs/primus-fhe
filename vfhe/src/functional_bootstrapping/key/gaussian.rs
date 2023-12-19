use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use algebra::{field::NTTField, ring::Ring};
use lattice::RGSW;
use num_traits::cast;

use super::FunctionalBootstrappingKey;

/// FHEW gaussian bootstrapping key
pub struct FHEWGaussianBootstrappingKey<R: Ring, F: NTTField> {
    data: Vec<Vec<RGSW<F>>>,
    basis: R::Base,
}

impl<R: Ring, F: NTTField, I: SliceIndex<[Vec<RGSW<F>>]>> IndexMut<I>
    for FHEWGaussianBootstrappingKey<R, F>
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<R: Ring, F: NTTField, I: SliceIndex<[Vec<RGSW<F>>]>> Index<I>
    for FHEWGaussianBootstrappingKey<R, F>
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<R1: Ring, F: NTTField> FHEWGaussianBootstrappingKey<R1, F> {
    /// Creates a new [`FHEWGaussianBootstrappingKey<R, F>`].
    #[inline]
    pub fn new(data: Vec<Vec<RGSW<F>>>, basis: R1::Base) -> Self {
        Self { data, basis }
    }

    /// Returns the basis of this [`FHEWGaussianBootstrappingKey<R, F>`].
    #[inline]
    pub fn basis(&self) -> R1::Base {
        self.basis
    }

    /// convert basis
    #[inline]
    pub fn basis_to_other_ring<R: Ring>(&self) -> R::Base {
        cast::<<R1 as Ring>::Base, <R as Ring>::Base>(self.basis).unwrap()
    }
}

impl<R1: Ring, F: NTTField> FunctionalBootstrappingKey for FHEWGaussianBootstrappingKey<R1, F> {
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
        let r_m = cast::<<R as Ring>::Inner, u64>(R::modulus()).unwrap();
        let r1_m = cast::<<R1 as Ring>::Inner, u64>(R1::modulus()).unwrap();
        assert!(r_m <= r1_m);

        let multiple = (r1_m.trailing_zeros() - r_m.trailing_zeros()) as usize;

        let basis = self.basis_to_other_ring::<R>();
        let basis_usize = cast::<<R as Ring>::Base, usize>(basis).unwrap();

        self.iter().zip(a).fold(acc, |mut acc, (s_i, &a_i)| {
            let decompose = a_i.decompose(basis);

            for (j, a_i_j) in decompose.into_iter().enumerate() {
                acc = acc.mul_with_rgsw(
                    &s_i[j * basis_usize + R::cast_into_usize(a_i_j.inner()) * multiple],
                );
            }
            acc
        })
    }
}
