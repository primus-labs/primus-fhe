use std::ops::Mul;

use algebra::{
    field::{NTTField, RandomNTTField},
    polynomial::Polynomial,
    ring::{RandomRing, Ring},
    RoundedDiv,
};
use num_traits::Zero;
use rand_distr::Distribution;

use crate::{
    LWEPlaintext, LWEPublicKey, LWESecretKey, LWESecretKeyDistribution, RLWEPublicKey,
    RLWESecretKey,
};

/// lwe parameter
#[derive(Debug, Clone)]
pub struct LWEParam<R: Ring> {
    /// the length of the vector a of the ciphertext
    n: usize,
    /// the message space modulus
    t: R::Inner,
    /// the cipher space modulus
    q: R::Inner,
    /// the noise error's standard deviation
    err_std_dev: f64,
    /// secret key
    secret_key: Option<LWESecretKey<R>>,
    /// public key
    public_key: LWEPublicKey<R>,
}

impl<R: Ring> LWEParam<R> {
    /// Creates a new [`LWEParam<R>`].
    pub fn new(n: usize, t: R::Inner, q: R::Inner, err_std_dev: f64) -> Self {
        Self {
            n,
            t,
            q,
            err_std_dev,
            secret_key: None,
            public_key: LWEPublicKey::default(),
        }
    }

    /// Returns the n of this [`LWEParam<R>`].
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the t of this [`LWEParam<R>`].
    #[inline]
    pub fn t(&self) -> <R as Ring>::Inner {
        self.t
    }

    /// Returns the q of this [`LWEParam<R>`].
    #[inline]
    pub fn q(&self) -> <R as Ring>::Inner {
        self.q
    }

    /// Returns the err std dev of this [`LWEParam<R>`].
    #[inline]
    pub fn err_std_dev(&self) -> f64 {
        self.err_std_dev
    }

    /// Returns the secret key of this [`LWEParam<R>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&LWESecretKey<R>> {
        self.secret_key.as_ref()
    }

    /// Returns a reference to the public key of this [`LWEParam<R>`].
    #[inline]
    pub fn public_key(&self) -> &LWEPublicKey<R> {
        &self.public_key
    }

    /// Sets the secret key of this [`LWEParam<R>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<LWESecretKey<R>>) {
        self.secret_key = secret_key;
    }

    /// Sets the public key of this [`LWEParam<R>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: LWEPublicKey<R>) {
        self.public_key = public_key;
    }

    /// encode
    pub fn encode(&self, value: R::Inner) -> LWEPlaintext<R> {
        debug_assert!(value < self.t);
        // Todo: `value * R::modulus()` may overflow, need fix
        R::from(value.mul(R::modulus()).rounded_div(self.t)).into()
    }

    /// decode
    pub fn decode(&self, plaintext: LWEPlaintext<R>) -> R::Inner {
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

impl<R: RandomRing> LWEParam<R> {
    /// generate binary secret key
    pub fn generate_binary_sk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        rng: Rng,
    ) -> LWESecretKey<R> {
        let secret_key = R::binary_distribution()
            .sample_iter(rng)
            .take(self.n)
            .collect();
        LWESecretKey::new(secret_key, LWESecretKeyDistribution::Binary)
    }

    /// generate ternary secret key
    pub fn generate_ternary_sk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        rng: Rng,
    ) -> LWESecretKey<R> {
        let secret_key = R::ternary_distribution()
            .sample_iter(rng)
            .take(self.n)
            .collect();
        LWESecretKey::new(secret_key, LWESecretKeyDistribution::Ternary)
    }
}

/// rlwe parameter
#[derive(Debug, Clone)]
pub struct RLWEParam<F: NTTField> {
    /// the length of the vector a of the ciphertext
    n: usize,
    /// the cipher space modulus
    q: F::Inner,
    /// the noise error's standard deviation
    err_std_dev: f64,
    /// secret key
    secret_key: Option<RLWESecretKey<F>>,
    /// public key
    public_key: RLWEPublicKey<F>,
}

impl<F: NTTField> RLWEParam<F> {
    /// Creates a new [`RLWEParam<F>`].
    #[inline]
    pub fn new(n: usize, q: F::Inner, err_std_dev: f64) -> Self {
        Self {
            n,
            q,
            err_std_dev,
            secret_key: None,
            public_key: RLWEPublicKey::default(),
        }
    }

    /// Returns the n of this [`RLWEParam<F>`].
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the q of this [`RLWEParam<F>`].
    #[inline]
    pub fn q(&self) -> <F as Ring>::Inner {
        self.q
    }

    /// Returns the err std dev of this [`RLWEParam<F>`].
    #[inline]
    pub fn err_std_dev(&self) -> f64 {
        self.err_std_dev
    }

    /// Returns the secret key of this [`RLWEParam<F>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&RLWESecretKey<F>> {
        self.secret_key.as_ref()
    }

    /// Returns a reference to the public key of this [`RLWEParam<F>`].
    #[inline]
    pub fn public_key(&self) -> &RLWEPublicKey<F> {
        &self.public_key
    }

    /// Sets the secret key of this [`RLWEParam<F>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<RLWESecretKey<F>>) {
        self.secret_key = secret_key;
    }

    /// Sets the public key of this [`RLWEParam<F>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: RLWEPublicKey<F>) {
        self.public_key = public_key;
    }
}

impl<F: RandomNTTField> RLWEParam<F> {
    /// generate secret key
    #[inline]
    pub fn generate_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> RLWESecretKey<F> {
        RLWESecretKey::new(Polynomial::random(self.n, rng))
    }

    /// generate public key
    #[inline]
    pub fn generate_pk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        sk: &RLWESecretKey<F>,
        mut rng: Rng,
    ) -> RLWEPublicKey<F> {
        let chi = F::normal_distribution(0.0, self.err_std_dev).unwrap();
        let a = <Polynomial<F>>::random(self.n, &mut rng);
        let b = <Polynomial<F>>::random_with_dis(self.n, &mut rng, chi) + &a * sk.data();
        (a, b).into()
    }
}
