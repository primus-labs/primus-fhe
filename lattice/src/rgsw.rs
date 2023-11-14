use std::ops::Mul;

use algebra::field::NTTField;

use crate::{
    rlwe::{RlweModeCoef, RlweModeNTT},
    GadgetRLWE, RLWE,
};

/// A generic rgsw struct type.
pub struct RGSW<F: NTTField> {
    d0: GadgetRLWE<F>,
    d1: GadgetRLWE<F>,
}

impl<F: NTTField> RGSW<F> {
    /// Creates a new [`RGSW<F>`].
    #[inline]
    pub fn new(d0: GadgetRLWE<F>, d1: GadgetRLWE<F>) -> Self {
        Self { d0, d1 }
    }

    /// Returns a reference to the basis of this [`RGSW<F>`].
    #[inline]
    pub fn basis(&self) -> &F::Modulus {
        self.d0.basis()
    }
}

impl<F: NTTField> Mul<RLWE<F>> for RGSW<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: RLWE<F>) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<F: NTTField> Mul<&RLWE<F>> for RGSW<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: &RLWE<F>) -> Self::Output {
        match rhs {
            RLWE::CoefMode(RlweModeCoef { a, b }) => self.d0 * a + self.d1 * b,
            RLWE::NttMode(RlweModeNTT { a, b }) => self.d0 * a + self.d1 * b,
        }
    }
}

impl<F: NTTField> Mul<RLWE<F>> for &RGSW<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: RLWE<F>) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<F: NTTField> Mul<&RLWE<F>> for &RGSW<F> {
    type Output = RLWE<F>;

    #[inline]
    fn mul(self, rhs: &RLWE<F>) -> Self::Output {
        match rhs {
            RLWE::CoefMode(RlweModeCoef { a, b }) => &self.d0 * a + &self.d1 * b,
            RLWE::NttMode(RlweModeNTT { a, b }) => &self.d0 * a + &self.d1 * b,
        }
    }
}

impl<F: NTTField> Mul<RGSW<F>> for RGSW<F> {
    type Output = RGSW<F>;

    #[inline]
    fn mul(self, rhs: RGSW<F>) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<F: NTTField> Mul<&RGSW<F>> for RGSW<F> {
    type Output = RGSW<F>;

    #[inline]
    fn mul(self, rhs: &RGSW<F>) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<F: NTTField> Mul<RGSW<F>> for &RGSW<F> {
    type Output = RGSW<F>;

    #[inline]
    fn mul(self, rhs: RGSW<F>) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<F: NTTField> Mul<&RGSW<F>> for &RGSW<F> {
    type Output = RGSW<F>;

    fn mul(self, rhs: &RGSW<F>) -> Self::Output {
        let basis = self.basis().clone();

        let nwe_d0_data: Vec<RLWE<F>> = rhs.d0.iter().map(|r| self * r).collect();
        let new_d0 = GadgetRLWE::new(nwe_d0_data, basis.clone());

        let nwe_d1_data: Vec<RLWE<F>> = rhs.d1.iter().map(|r| self * r).collect();
        let new_d1 = GadgetRLWE::new(nwe_d1_data, basis.clone());

        <RGSW<F>>::new(new_d0, new_d1)
    }
}
