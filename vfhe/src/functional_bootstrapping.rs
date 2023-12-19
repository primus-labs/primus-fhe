use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::{RGSW, RLWE};
use num_traits::cast;

pub(crate) fn init_nand_acc<R: Ring, F: NTTField>(
    mut b: R,
    q: <R as Ring>::Inner,
    big_n: usize,
    big_q: <F as Ring>::Inner,
) -> RLWE<F> {
    let mut v = Polynomial::zero_with_coeff_count(big_n);

    let step = big_n * 2 / R::cast_into_usize(q);
    let step_r = R::cast_from_usize(step);

    let l = (cast::<u8, <R as Ring>::Inner>(3).unwrap() * q) >> 3;
    let r = (cast::<u8, <R as Ring>::Inner>(7).unwrap() * q) >> 3;

    v.iter_mut().step_by(step).for_each(|a| {
        if (l..r).contains(&b.inner()) {
            *a = F::from(big_q >> 3);
        } else {
            *a = -F::from(big_q >> 3);
        }
        b -= step_r;
    });
    RLWE::from(v)
}

/// TFHE binary bootstrapping key
pub struct TFHEBinaryBootStrappingKey<F: NTTField> {
    data: Vec<RGSW<F>>,
}

impl<F: NTTField, I: SliceIndex<[RGSW<F>]>> IndexMut<I> for TFHEBinaryBootStrappingKey<F> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.data, index)
    }
}

impl<F: NTTField, I: SliceIndex<[RGSW<F>]>> Index<I> for TFHEBinaryBootStrappingKey<F> {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.data, index)
    }
}

impl<F: NTTField> TFHEBinaryBootStrappingKey<F> {
    /// Creates a new [`TFHEBinaryBootStrappingKey<F>`].
    #[inline]
    pub fn new(data: Vec<RGSW<F>>) -> Self {
        Self { data }
    }

    /// length
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// TFHE ternary bootstrapping key
pub struct TFHETernaryBootStrappingKey<F: NTTField> {
    data: Vec<(RGSW<F>, RGSW<F>)>,
}

impl<F: NTTField> TFHETernaryBootStrappingKey<F> {
    /// Creates a new [`TFHETernaryBootStrappingKey<F>`].
    #[inline]
    pub fn new(data: Vec<(RGSW<F>, RGSW<F>)>) -> Self {
        Self { data }
    }
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

/// FHEW gaussian bootstrapping key
pub struct FHEWGaussianBootstrappingKey<F: NTTField> {
    data: Vec<Vec<RGSW<F>>>,
}

impl<F: NTTField> FHEWGaussianBootstrappingKey<F> {
    /// Creates a new [`FHEWGaussianBootstrappingKey<F>`].
    pub fn new(data: Vec<Vec<RGSW<F>>>) -> Self {
        Self { data }
    }
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
