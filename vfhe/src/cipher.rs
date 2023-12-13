use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};
use lattice::{LWE, RLWE};

use crate::Vfhe;

/// cipher text
#[derive(Debug, Clone)]
pub struct LWECiphertext<R: Ring> {
    data: LWE<R>,
}

impl<R: Ring> From<(Vec<R>, R)> for LWECiphertext<R> {
    #[inline]
    fn from((a, b): (Vec<R>, R)) -> Self {
        Self {
            data: <LWE<R>>::new(a, b),
        }
    }
}

impl<R: Ring> From<LWE<R>> for LWECiphertext<R> {
    #[inline]
    fn from(value: LWE<R>) -> Self {
        Self { data: value }
    }
}

impl<R: Ring> LWECiphertext<R> {
    /// Creates a new [`LWECiphertext<R>`].
    #[inline]
    pub fn new(data: LWE<R>) -> Self {
        Self { data }
    }

    /// Returns a reference to the data of this [`LWECiphertext<R>`].
    #[inline]
    pub fn data(&self) -> &LWE<R> {
        &self.data
    }

    /// Perform component-wise addition.
    #[inline]
    pub fn no_boot_add(self, rhs: &LWECiphertext<R>) -> Self {
        Self {
            data: self.data.add_component_wise(rhs.data()),
        }
    }
}

/// cipher text
#[derive(Debug, Clone)]
pub struct RLWECiphertext<F: NTTField> {
    data: RLWE<F>,
}

impl<F: NTTField> RLWECiphertext<F> {
    /// Returns a reference to the data of this [`RLWECiphertext<F>`].
    #[inline]
    pub fn data(&self) -> &RLWE<F> {
        &self.data
    }
}

impl<F: NTTField> From<(Polynomial<F>, Polynomial<F>)> for RLWECiphertext<F> {
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self {
            data: RLWE::new(a, b),
        }
    }
}

impl<F: NTTField> From<RLWE<F>> for RLWECiphertext<F> {
    #[inline]
    fn from(data: RLWE<F>) -> Self {
        Self { data }
    }
}
