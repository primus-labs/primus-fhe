use std::ops::{Deref, DerefMut};

use algebra::{Field, NTTField, Polynomial};

use crate::{NTTRLWE, RLWE};

/// Performs dot product for two slices
#[inline]
pub fn dot_product<F: Field>(u: &[F], v: &[F]) -> F {
    debug_assert_eq!(u.len(), v.len());
    u.iter().zip(v).fold(F::ZERO, |acc, (&x, y)| acc + x * y)
}

/// Pre allocated space for inplace decomposition.
#[derive(Debug)]
pub struct DecompositionSpace<F: NTTField> {
    space: Polynomial<F>,
}

impl<F: NTTField> Deref for DecompositionSpace<F> {
    type Target = Polynomial<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.space
    }
}

impl<F: NTTField> DerefMut for DecompositionSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.space
    }
}

impl<F: NTTField> DecompositionSpace<F> {
    /// Creates a new [`DecompositionSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self {
            space: <Polynomial<F>>::zero_with_coeff_count(coeff_count),
        }
    }

    /// Gets the pre allocated space of decomposition.
    #[inline]
    pub fn get(&self) -> &Polynomial<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space of decomposition.
    #[inline]
    pub fn get_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.space
    }
}

/// Pre allocated space for inplace polynomial operation.
#[derive(Debug)]
pub struct PolynomialSpace<F: NTTField> {
    space: Polynomial<F>,
}

impl<F: NTTField> Deref for PolynomialSpace<F> {
    type Target = Polynomial<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.space
    }
}

impl<F: NTTField> DerefMut for PolynomialSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.space
    }
}

impl<F: NTTField> PolynomialSpace<F> {
    /// Creates a new [`PolynomialSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self {
            space: <Polynomial<F>>::zero_with_coeff_count(coeff_count),
        }
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &Polynomial<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut Polynomial<F> {
        &mut self.space
    }

    /// Returns the coeff count of this [`PolynomialSpace<F>`].
    #[inline]
    pub fn coeff_count(&self) -> usize {
        self.space.coeff_count()
    }

    /// Copies all coefficients from `src` into `self`, using a memcpy.
    #[inline]
    pub fn copy_from_polynomial(&mut self, src: &Polynomial<F>) {
        self.as_mut_slice().copy_from_slice(src.as_slice());
    }
}

/// Pre allocated space.
#[derive(Debug)]
pub struct NTTRLWESpace<F: NTTField> {
    space: NTTRLWE<F>,
}

impl<F: NTTField> Deref for NTTRLWESpace<F> {
    type Target = NTTRLWE<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.space
    }
}

impl<F: NTTField> DerefMut for NTTRLWESpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.space
    }
}

impl<F: NTTField> NTTRLWESpace<F> {
    /// Creates a new [`NTTRLWESpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self {
            space: <NTTRLWE<F>>::zero(coeff_count),
        }
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &NTTRLWE<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut NTTRLWE<F> {
        &mut self.space
    }
}

/// Pre allocated space.
#[derive(Debug)]
pub struct RLWESpace<F: NTTField> {
    space: RLWE<F>,
}

impl<F: NTTField> Deref for RLWESpace<F> {
    type Target = RLWE<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.space
    }
}

impl<F: NTTField> DerefMut for RLWESpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.space
    }
}

impl<F: NTTField> RLWESpace<F> {
    /// Creates a new [`RLWESpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self {
            space: <RLWE<F>>::zero(coeff_count),
        }
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &RLWE<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut RLWE<F> {
        &mut self.space
    }
}
