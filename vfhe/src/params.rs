use std::ops::Mul;

use algebra::{
    ring::{RandomRing, Ring},
    RoundedDiv,
};
use num_traits::Zero;
use rand_distr::Distribution;

use crate::{Plaintext, PublicKey, SecretKey, SecretKeyDistribution};

/// lwe parameter
#[derive(Debug, Clone)]
pub struct LweParam<R: Ring> {
    /// the length of the vector a of the ciphertext
    n: usize,
    /// the message space modulus
    t: R::Inner,
    /// the cipher space modulus
    q: R::Inner,
    /// the noise error's standard deviation
    err_std_dev: f64,
    /// secret key
    secret_key: Option<SecretKey<R>>,
    /// public key
    public_key: PublicKey<R>,
}

impl<R: Ring> LweParam<R> {
    /// Creates a new [`LweParam<R>`].
    pub fn new(n: usize, t: R::Inner, q: R::Inner, err_std_dev: f64) -> Self {
        Self {
            n,
            t,
            q,
            err_std_dev,
            secret_key: None,
            public_key: PublicKey::default(),
        }
    }

    /// Returns the n of this [`LweParam<R>`].
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the t of this [`LweParam<R>`].
    #[inline]
    pub fn t(&self) -> <R as Ring>::Inner {
        self.t
    }

    /// Returns the q of this [`LweParam<R>`].
    #[inline]
    pub fn q(&self) -> <R as Ring>::Inner {
        self.q
    }

    /// Returns the err std dev of this [`LweParam<R>`].
    #[inline]
    pub fn err_std_dev(&self) -> f64 {
        self.err_std_dev
    }

    /// Returns the secret key of this [`LweParam<R>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&SecretKey<R>> {
        self.secret_key.as_ref()
    }

    /// Returns a reference to the public key of this [`LweParam<R>`].
    #[inline]
    pub fn public_key(&self) -> &PublicKey<R> {
        &self.public_key
    }

    /// Sets the secret key of this [`LweParam<R>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<SecretKey<R>>) {
        self.secret_key = secret_key;
    }

    /// Sets the public key of this [`LweParam<R>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: PublicKey<R>) {
        self.public_key = public_key;
    }

    /// encode
    pub fn encode(&self, value: R::Inner) -> Plaintext<R> {
        debug_assert!(value < self.t);
        // Todo: `value * R::modulus()` may overflow, need fix
        R::from(value.mul(R::modulus()).rounded_div(self.t)).into()
    }

    /// decode
    pub fn decode(&self, plaintext: Plaintext<R>) -> R::Inner {
        let r = plaintext
            .data()
            .inner()
            .mul(self.t)
            .rounded_div(R::modulus());
        if r == self.t {
            R::Inner::zero()
        } else {
            r
        }
    }
}

impl<R: RandomRing> LweParam<R> {
    /// generate binary secret key
    pub fn generate_binary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        let secret_key = R::binary_distribution()
            .sample_iter(rng)
            .take(self.n)
            .collect();
        SecretKey::new(secret_key, SecretKeyDistribution::Binary)
    }

    /// generate ternary secret key
    pub fn generate_ternary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        let secret_key = R::ternary_distribution()
            .sample_iter(rng)
            .take(self.n)
            .collect();
        SecretKey::new(secret_key, SecretKeyDistribution::Ternary)
    }
}
