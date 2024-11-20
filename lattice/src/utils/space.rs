use std::ops::{Deref, DerefMut};

use algebra::{Basis, NTTField, NTTPolynomial, Polynomial};

use crate::{NTTRGSW, NTTRLWE, RLWE};

/// Pre allocated space for inplace decomposition.
#[derive(Debug)]
pub struct DecompositionSpace<F: NTTField> {
    space: NTTPolynomial<F>,
}

impl<F: NTTField> Deref for DecompositionSpace<F> {
    type Target = NTTPolynomial<F>;

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
            space: <NTTPolynomial<F>>::zero(coeff_count),
        }
    }

    /// Gets the pre allocated space of decomposition.
    #[inline]
    pub fn get(&self) -> &NTTPolynomial<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space of decomposition.
    #[inline]
    pub fn get_mut(&mut self) -> &mut NTTPolynomial<F> {
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
            space: <Polynomial<F>>::zero(coeff_count),
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
}

/// Pre allocated space for inplace ntt polynomial operation.
#[derive(Debug)]
pub struct NTTPolynomialSpace<F: NTTField> {
    space: NTTPolynomial<F>,
}

impl<F: NTTField> Deref for NTTPolynomialSpace<F> {
    type Target = NTTPolynomial<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.space
    }
}

impl<F: NTTField> DerefMut for NTTPolynomialSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.space
    }
}

impl<F: NTTField> NTTPolynomialSpace<F> {
    /// Creates a new [`NTTPolynomialSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize) -> Self {
        Self {
            space: <NTTPolynomial<F>>::zero(coeff_count),
        }
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &NTTPolynomial<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut NTTPolynomial<F> {
        &mut self.space
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

/// Pre allocated space.
#[derive(Debug)]
pub struct NTTRGSWSpace<F: NTTField> {
    space: NTTRGSW<F>,
}

impl<F: NTTField> Deref for NTTRGSWSpace<F> {
    type Target = NTTRGSW<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.space
    }
}

impl<F: NTTField> DerefMut for NTTRGSWSpace<F> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.space
    }
}

impl<F: NTTField> NTTRGSWSpace<F> {
    /// Creates a new [`NTTRGSWSpace<F>`].
    #[inline]
    pub fn new(coeff_count: usize, basis: Basis<F>) -> Self {
        Self {
            space: NTTRGSW::zero(coeff_count, basis),
        }
    }

    /// Gets the pre allocated space.
    #[inline]
    pub fn get(&self) -> &NTTRGSW<F> {
        &self.space
    }

    /// Gets the mutable pre allocated space.
    #[inline]
    pub fn get_mut(&mut self) -> &mut NTTRGSW<F> {
        &mut self.space
    }
}
