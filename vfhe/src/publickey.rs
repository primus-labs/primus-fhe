use algebra::{field::NTTField, polynomial::Polynomial, ring::Ring};

use crate::{LWECiphertext, RLWECiphertext};

/// public key
#[derive(Debug, Clone)]
pub struct LWEPublicKey<R: Ring> {
    data: Vec<LWECiphertext<R>>,
}

impl<R: Ring> From<Vec<LWECiphertext<R>>> for LWEPublicKey<R> {
    #[inline]
    fn from(value: Vec<LWECiphertext<R>>) -> Self {
        Self { data: value }
    }
}

impl<R: Ring> Default for LWEPublicKey<R> {
    #[inline]
    fn default() -> Self {
        Self { data: Vec::new() }
    }
}

impl<R: Ring> LWEPublicKey<R> {
    /// Creates a new [`LWEPublicKey<R>`].
    #[inline]
    pub fn new(data: Vec<LWECiphertext<R>>) -> Self {
        Self { data }
    }

    /// Returns a reference to the data of this [`LWEPublicKey<R>`].
    #[inline]
    pub fn data(&self) -> &[LWECiphertext<R>] {
        self.data.as_ref()
    }
}

/// public key
#[derive(Debug, Clone)]
pub struct RLWEPublicKey<F: NTTField> {
    data: RLWECiphertext<F>,
}

impl<F: NTTField> From<(Polynomial<F>, Polynomial<F>)> for RLWEPublicKey<F> {
    #[inline]
    fn from((a, b): (Polynomial<F>, Polynomial<F>)) -> Self {
        Self {
            data: RLWECiphertext::from((a, b)),
        }
    }
}

impl<F: NTTField> Default for RLWEPublicKey<F> {
    #[inline]
    fn default() -> Self {
        let e = Polynomial::new(Vec::new());
        Self {
            data: RLWECiphertext::from((e.clone(), e)),
        }
    }
}

impl<F: NTTField> RLWEPublicKey<F> {
    /// Returns a reference to the data of this [`RLWEPublicKey<F>`].
    #[inline]
    pub fn data(&self) -> &RLWECiphertext<F> {
        &self.data
    }

    /// Returns a reference to the a of this [`RLWEPublicKey<F>`].
    #[inline]
    pub fn a(&self) -> &Polynomial<F> {
        self.data.a()
    }

    /// Returns a reference to the b of this [`RLWEPublicKey<F>`].
    #[inline]
    pub fn b(&self) -> &Polynomial<F> {
        self.data.b()
    }
}
