use std::marker::PhantomData;

use algebra::ring::{RandomRing, Ring};
use rand_distr::Distribution;

use crate::seckey::SecretKey;

/// key generator
#[derive(Debug, Clone)]
pub struct KeyGenerator<R: Ring> {
    len: usize,
    marker: PhantomData<R>,
}

impl<R: Ring> KeyGenerator<R> {
    /// Creates a new [`KeyGenerator<R>`].
    #[inline]
    pub fn new(len: usize) -> Self {
        Self {
            len,
            marker: PhantomData,
        }
    }
}

impl<R: RandomRing> KeyGenerator<R> {
    /// generate binary secret key
    pub fn generate_binary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        let secret_key = R::binary_distribution()
            .sample_iter(rng)
            .take(self.len)
            .collect();
        SecretKey::new(secret_key)
    }

    /// generate ternary secret key
    pub fn generate_ternary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        let secret_key = R::ternary_distribution()
            .sample_iter(rng)
            .take(self.len)
            .collect();
        SecretKey::new(secret_key)
    }
}
