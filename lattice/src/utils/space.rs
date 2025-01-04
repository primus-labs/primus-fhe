use std::ops::{Deref, DerefMut};

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    Field, NttField,
};

use crate::{NttRgsw, NttRlwe, Rlwe};

/// Pre allocated space for inplace decomposition.
pub struct PolyDecomposeSpace<F: NttField> {
    /// store adjusted polynomial
    pub adjust_poly: FieldPolynomial<F>,
    /// store decompose polynomial
    pub decomposed_poly: FieldNttPolynomial<F>,
    /// store carries
    pub carries: Vec<bool>,
}

impl<F: NttField> PolyDecomposeSpace<F> {
    /// Creates a new [`PolyDecomposeSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self {
            adjust_poly: FieldPolynomial::zero(coeff_count),
            decomposed_poly: FieldNttPolynomial::zero(coeff_count),
            carries: vec![false; coeff_count],
        }
    }

    /// Gets the mutable pre allocated space for decomposition.
    #[inline]
    pub fn get_mut(
        &mut self,
    ) -> (
        &mut FieldPolynomial<F>,
        &mut [bool],
        &mut FieldNttPolynomial<F>,
    ) {
        (
            &mut self.adjust_poly,
            self.carries.as_mut_slice(),
            &mut self.decomposed_poly,
        )
    }
}

/// Pre allocated space.
pub struct RlweSpace<F: NttField>(Rlwe<F>);

impl<F: NttField> Deref for RlweSpace<F> {
    type Target = Rlwe<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: NttField> DerefMut for RlweSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: NttField> RlweSpace<F> {
    /// Creates a new [`RlweSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self(<Rlwe<F>>::zero(coeff_count))
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &Rlwe<F> {
        &self.0
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut Rlwe<F> {
        &mut self.0
    }
}

/// Pre allocated space.
pub struct NttRlweSpace<F: NttField>(NttRlwe<F>);

impl<F: NttField> Deref for NttRlweSpace<F> {
    type Target = NttRlwe<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: NttField> DerefMut for NttRlweSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: NttField> NttRlweSpace<F> {
    /// Creates a new [`NttRlweSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self(<NttRlwe<F>>::zero(coeff_count))
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &NttRlwe<F> {
        &self.0
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut NttRlwe<F> {
        &mut self.0
    }
}

/// Pre allocated space.
pub struct NttRgswSpace<F: NttField>(NttRgsw<F>);

impl<F: NttField> Deref for NttRgswSpace<F> {
    type Target = NttRgsw<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: NttField> DerefMut for NttRgswSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: NttField> NttRgswSpace<F> {
    /// Creates a new [`NttRgswSpace<F>`].
    #[inline]
    pub fn new(
        coeff_count: usize,
        basis: NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
    ) -> Self {
        Self(NttRgsw::zero(coeff_count, basis))
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &NttRgsw<F> {
        &self.0
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut NttRgsw<F> {
        &mut self.0
    }
}
