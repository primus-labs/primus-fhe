use algebra::{Basis, NTTField, Polynomial, Random, RandomNTTField, RandomRing, Ring, RoundedDiv};
use lattice::{dot_product, GadgetRLWE, RGSW};
use num_traits::{CheckedMul, Zero};
use rand::seq::SliceRandom;
use rand_distr::Distribution;

use crate::{
    secretkey::NTTRLWESecretKey, LWECiphertext, LWEPlaintext, LWEPublicKey, LWESecretKey,
    LWESecretKeyDistribution, RLWECiphertext, RLWEPlaintext, RLWEPublicKey, RLWESecretKey,
};

/// The parameter for lwe
#[derive(Debug, Clone)]
pub struct LWEParam<R: Ring> {
    /// The length of the vector `a` of the [`LWECiphertext<R>`]
    n: usize,
    /// The message space modulus value
    t: R::Inner,
    /// The cipher space modulus value
    q: R::Inner,
    /// The noise error's standard deviation
    err_std_dev: f64,
    /// LWE Secret Key distribution
    secret_key_distribution: LWESecretKeyDistribution,
    /// LWE Secret Key
    secret_key: Option<LWESecretKey<R>>,
    /// LWE Public Key
    public_key: LWEPublicKey<R>,
}

impl<R: Ring> LWEParam<R> {
    /// Creates a new [`LWEParam<R>`].
    pub fn new(
        n: usize,
        t: R::Inner,
        err_std_dev: f64,
        secret_key_distribution: LWESecretKeyDistribution,
    ) -> Self {
        Self {
            n,
            t,
            q: R::modulus_value(),
            err_std_dev,
            secret_key_distribution,
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

    /// Returns the noise error's standard deviation of this [`LWEParam<R>`].
    #[inline]
    pub fn err_std_dev(&self) -> f64 {
        self.err_std_dev
    }

    /// Returns the lwe secret key distribution of this [`LWEParam<R>`].
    #[inline]
    pub fn secret_key_distribution(&self) -> LWESecretKeyDistribution {
        self.secret_key_distribution
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

    /// Encodes a value from message space into LWE Plaintext
    pub fn encode(&self, value: R::Inner) -> LWEPlaintext<R> {
        debug_assert!(value < self.t);
        R::from(
            value
                .checked_mul(&R::modulus_value())
                .unwrap()
                .rounded_div(self.t),
        )
    }

    /// Decodes a LWE Plaintext into a value of message space
    pub fn decode(&self, plain: LWEPlaintext<R>) -> R::Inner {
        debug_assert!(plain.inner() < self.q);

        let r = plain
            .inner()
            .checked_mul(&self.t)
            .unwrap()
            .rounded_div(R::modulus_value());

        debug_assert!(r <= self.t);

        if r == self.t {
            R::Inner::zero()
        } else {
            r
        }
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    pub fn decrypt(&self, cipher: &LWECiphertext<R>) -> LWEPlaintext<R> {
        match self.secret_key {
            Some(ref s) => cipher.b() - dot_product(cipher.a(), s),
            None => panic!("Decryption should supply secret key"),
        }
    }
}

impl<R: RandomRing> LWEParam<R> {
    /// Gets the error distribution based on the [`LWEParam<R>`].
    #[inline]
    pub fn error_distribution(&self) -> <R as Random>::NormalDistribution {
        R::normal_distribution(0.0, self.err_std_dev).unwrap()
    }

    /// Generates [`LWESecretKey<R>`] randomly.
    pub fn generate_sk<Rng>(&self, rng: Rng) -> LWESecretKey<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        match self.secret_key_distribution {
            LWESecretKeyDistribution::Binary => R::binary_distribution()
                .sample_iter(rng)
                .take(self.n)
                .collect(),
            LWESecretKeyDistribution::Ternary => R::ternary_distribution()
                .sample_iter(rng)
                .take(self.n)
                .collect(),
        }
    }

    /// Generates [`LWEPublicKey<R>`] randomly.
    pub fn generate_pk<Rng>(&self, s: &LWESecretKey<R>, mut rng: Rng) -> LWEPublicKey<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let dis = R::standard_distribution();
        let n = self.n;
        let chi = self.error_distribution();

        (0..32)
            .map(|_| {
                let a: Vec<R> = dis.sample_iter(&mut rng).take(n).collect();
                let b = dot_product(&a, s) + chi.sample(&mut rng);
                LWECiphertext::new(a, b)
            })
            .collect::<Vec<LWECiphertext<R>>>()
    }

    /// Encrypts [`LWEPlaintext<R>`] into [`LWECiphertext<R>`] by [`LWEPublicKey<R>`]
    pub fn encrypt_by_pk<Rng>(&self, plain: LWEPlaintext<R>, mut rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let n = self.n;
        let chi = self.error_distribution();

        let cipher = LWECiphertext::new(vec![R::zero(); n], plain + chi.sample(&mut rng));

        self.public_key()
            .choose_multiple(&mut rng, 2)
            .fold(cipher, |acc, choice| acc.add_component_wise(choice))
    }

    /// Encrypts [`LWEPlaintext<R>`] into [`LWECiphertext<R>`] by [`LWESecretKey<R>`]
    pub fn encrypt_by_sk<Rng>(&self, plain: LWEPlaintext<R>, mut rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        match self.secret_key {
            Some(ref s) => {
                let dis = R::standard_distribution();
                let n = self.n;
                let chi = self.error_distribution();

                let a: Vec<R> = dis.sample_iter(&mut rng).take(n).collect();
                let b = dot_product(&a, s) + plain + chi.sample(&mut rng);

                LWECiphertext::new(a, b)
            }
            None => panic!("`encrypt_by_sk` should supply secret key"),
        }
    }
}

/// The parameter for rlwe and rgsw
#[derive(Debug, Clone)]
pub struct RingParam<F: NTTField> {
    /// The length of the vector `a` of the [`RLWECiphertext`]
    n: usize,
    /// The cipher space modulus value, refers to **`Q`** in the paper.
    q: F::Inner,
    /// Decompose basis for `Q` used for bootstrapping accumulator
    bg: Basis<F>,
    /// bg's powers
    bgs: Vec<F>,
    /// b ** d >= p
    dg: usize,
    /// The noise error's standard deviation
    err_std_dev: f64,
    /// RLWE Secret Key
    secret_key: Option<(RLWESecretKey<F>, NTTRLWESecretKey<F>)>,
    /// RLWE Public Key
    public_key: RLWEPublicKey<F>,
}

impl<F: NTTField> RingParam<F> {
    /// Creates a new [`RingParam<F>`].
    #[inline]
    pub fn new(n: usize, bg_bits: u32, err_std_dev: f64) -> Self {
        let bg = <Basis<F>>::new(bg_bits);
        let bf = F::new(bg.basis());
        let dg = bg.decompose_len();

        let mut bs = vec![F::zero(); dg];
        let mut temp = F::one();
        bs.iter_mut().for_each(|v| {
            *v = temp;
            temp *= bf;
        });

        Self {
            n,
            q: F::modulus_value(),
            bg,
            dg,
            bgs: bs,
            err_std_dev,
            secret_key: None,
            public_key: RLWEPublicKey::default(),
        }
    }

    /// Returns the n of this [`RingParam<F>`], refers to **`N`** in the paper.
    #[inline]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Returns the q of this [`RingParam<F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn q(&self) -> <F as Ring>::Inner {
        self.q
    }

    /// Returns the gadget basis of this [`RingParam<F>`].
    #[inline]
    pub fn bg(&self) -> Basis<F> {
        self.bg
    }

    /// Returns the gadget basis degree of this [`RingParam<F>`].
    #[inline]
    pub fn dg(&self) -> usize {
        self.dg
    }

    /// Returns a reference to the gadget basis powers of this [`RingParam<F>`].
    #[inline]
    pub fn bgs(&self) -> &[F] {
        self.bgs.as_ref()
    }

    /// Returns the noise error's standard deviation of this [`RingParam<F>`].
    #[inline]
    pub fn err_std_dev(&self) -> f64 {
        self.err_std_dev
    }

    /// Returns the RLWE Secret Key of this [`RingParam<F>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&(RLWESecretKey<F>, NTTRLWESecretKey<F>)> {
        self.secret_key.as_ref()
    }

    /// Returns a reference to the RLWE Public Key of this [`RingParam<F>`].
    #[inline]
    pub fn public_key(&self) -> &RLWEPublicKey<F> {
        &self.public_key
    }

    /// Sets the RLWE Secret Key of this [`RingParam<F>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<(RLWESecretKey<F>, NTTRLWESecretKey<F>)>) {
        self.secret_key = secret_key;
    }

    /// Sets the RLWE Public Key of this [`RingParam<F>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: RLWEPublicKey<F>) {
        self.public_key = public_key;
    }

    /// Decrypts the [`RLWECiphertext<F>`] back to [`RLWEPlaintext<F>`]
    #[inline]
    pub fn decrypt(&self, ciphertext: RLWECiphertext<F>) -> RLWEPlaintext<F> {
        match self.secret_key {
            Some(ref sk) => ciphertext.b() - ciphertext.a() * &sk.1,
            None => panic!("`decrypt` should supply secret key"),
        }
    }
}

impl<F: RandomNTTField> RingParam<F> {
    /// Gets the error distribution based on the [`RingParam<F>`].
    #[inline]
    pub fn error_distribution(&self) -> <F as Random>::NormalDistribution {
        F::normal_distribution(0.0, self.err_std_dev).unwrap()
    }

    /// Generates RLWE Secret Key[`RLWESecretKey<F>`]
    #[inline]
    pub fn generate_sk<Rng>(&self, rng: Rng) -> RLWESecretKey<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        Polynomial::random(self.n, rng)
    }

    /// Generates RLWE Public Key [`RLWEPublicKey<F>`]
    #[inline]
    pub fn generate_pk<Rng>(&self, s: &NTTRLWESecretKey<F>, mut rng: Rng) -> RLWEPublicKey<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let chi = self.error_distribution();
        let a = <Polynomial<F>>::random(self.n, &mut rng);
        let b = <Polynomial<F>>::random_with_dis(self.n, &mut rng, chi) + &a * s;
        <RLWEPublicKey<F>>::new(a, b)
    }

    /// Encrypts [`RLWEPlaintext<F>`] into [`RLWECiphertext<F>`] by [`NTTRLWESecretKey<F>`]
    pub fn encrypt_by_sk<Rng>(&self, plain: &RLWEPlaintext<F>, mut rng: Rng) -> RLWECiphertext<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let sk = self.secret_key().unwrap();
        let chi = self.error_distribution();

        let a = <Polynomial<F>>::random_with_dis(self.n, &mut rng, F::standard_distribution());
        let b = <Polynomial<F>>::random_with_dis(self.n, &mut rng, chi) + plain + &a * &sk.1;

        RLWECiphertext::new(a, b)
    }

    /// Encrypts [`RLWEPlaintext<F>`] into [`RLWECiphertext<F>`] by [`RLWEPublicKey<F>`]
    pub fn encrypt_by_pk<Rng>(&self, plain: &RLWEPlaintext<F>, mut rng: Rng) -> RLWECiphertext<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let pk = &self.public_key;
        let chi = self.error_distribution();

        let v = <Polynomial<F>>::random_with_dis(self.n, &mut rng, F::ternary_distribution())
            .to_ntt_polynomial();

        let a = <Polynomial<F>>::random_with_dis(self.n, &mut rng, chi) + pk.a() * &v;
        let b = <Polynomial<F>>::random_with_dis(self.n, &mut rng, chi) + plain + pk.b() * v;

        RLWECiphertext::new(a, b)
    }

    /// Generates many RLWE Ciphertext which are encryptions of 0 by [`NTTRLWESecretKey<F>`].
    pub fn fresh_zeros_by_sk<Rng>(
        &self,
        mut rng: Rng,
        sk: &NTTRLWESecretKey<F>,
        num: usize,
    ) -> Vec<RLWECiphertext<F>>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let chi = self.error_distribution();
        (0..num)
            .map(|_| {
                let a = <Polynomial<F>>::random(self.n, &mut rng);
                let b = <Polynomial<F>>::random_with_dis(self.n, &mut rng, chi) + &a * sk;
                <RLWECiphertext<F>>::new(a, b)
            })
            .collect()
    }

    /// Generates `RGSW(0)` by [`NTTRLWESecretKey<F>`].
    pub fn rgsw_zero_by_sk<Rng>(&self, mut rng: Rng, sk: &NTTRLWESecretKey<F>) -> RGSW<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let m = self.fresh_zeros_by_sk(&mut rng, sk, self.dg);
        let neg_sm = self.fresh_zeros_by_sk(&mut rng, sk, self.dg);
        RGSW::new(
            GadgetRLWE::new(neg_sm, self.bg),
            GadgetRLWE::new(m, self.bg),
        )
    }

    /// Sets `RGSW(0)` to `RGSW(1)`
    pub fn rgsw_zero_to_one(&self, rgsw: &mut RGSW<F>) {
        rgsw.c_m_mut()
            .iter_mut()
            .zip(self.bgs.iter())
            .for_each(|(c_zero, &bi)| {
                c_zero.b_mut()[0] += bi;
            });
        rgsw.c_neg_s_m_mut()
            .iter_mut()
            .zip(self.bgs.iter())
            .for_each(|(c_zero, &bi)| {
                c_zero.a_mut()[0] += bi;
            });
    }
}
