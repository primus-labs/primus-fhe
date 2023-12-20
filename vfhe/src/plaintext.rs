use std::ops::Mul;

use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring, RoundedDiv};

/// LWE Plaintext type
#[derive(Debug, Clone, Copy)]
pub struct LWEPlaintext<R: Ring> {
    data: R,
}

impl<R: Ring> From<R> for LWEPlaintext<R> {
    #[inline]
    fn from(data: R) -> Self {
        Self { data }
    }
}

impl<R: Ring> LWEPlaintext<R> {
    /// Creates a new [`LWEPlaintext<R>`].
    #[inline]
    pub fn new(data: R) -> Self {
        Self { data }
    }

    /// Returns the data of this [`LWEPlaintext<R>`].
    #[inline]
    pub fn data(&self) -> R {
        self.data
    }

    /// Encode a value into [`LWEPlaintext<R>`].
    #[inline]
    pub fn encode(value: R::Inner, m_space: R::Inner) -> Self {
        debug_assert!(value < m_space);
        Self {
            data: R::from(value.mul(R::modulus()).rounded_div(m_space)),
        }
    }

    /// decode
    #[inline]
    pub fn decode(self, m_space: R::Inner) -> R::Inner {
        self.data.inner().mul(m_space).rounded_div(R::modulus())
    }
}

/// RLWE Plaintext type
#[derive(Debug, Clone)]
pub struct RLWEPlaintext<F: NTTField> {
    data: Polynomial<F>,
}

impl<F: NTTField> RLWEPlaintext<F> {
    /// Returns a reference to the data of this [`RLWEPlaintext<F>`].
    #[inline]
    pub fn data(&self) -> &Polynomial<F> {
        &self.data
    }
}

impl<F: NTTField> From<Polynomial<F>> for RLWEPlaintext<F> {
    #[inline]
    fn from(data: Polynomial<F>) -> Self {
        Self { data }
    }
}
