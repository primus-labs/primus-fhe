use std::ops::Mul;

use algebra::{ring::Ring, RoundedDiv};

/// Plaintext type
#[derive(Debug, Clone, Copy)]
pub struct Plaintext<R: Ring> {
    data: R,
}

impl<R: Ring> From<R> for Plaintext<R> {
    #[inline]
    fn from(data: R) -> Self {
        Self { data }
    }
}

impl<R: Ring> Plaintext<R> {
    /// Creates a new [`Plaintext<R>`].
    #[inline]
    pub fn new(data: R) -> Self {
        Self { data }
    }

    /// Returns the data of this [`Plaintext<R>`].
    #[inline]
    pub fn data(&self) -> R {
        self.data
    }

    /// Encode a value into [`Plaintext<R>`].
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
