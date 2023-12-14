use algebra::{
    field::{NTTField, RandomNTTField},
    polynomial::Polynomial,
    ring::{RandomRing, Ring},
};
use lattice::{dot_product, RLWE};
use num_traits::cast;
use rand::seq::SliceRandom;
use rand_distr::Distribution;

use crate::{LWECiphertext, LWEParam, LWEPlaintext, LWEPublicKey, LWESecretKey, RLWEParam};

/// fhe scheme
#[derive(Debug, Clone)]
pub struct Vfhe<R: Ring, F: NTTField> {
    lwe_param: LWEParam<R>,
    rlwe_param: RLWEParam<F>,
}

impl<R: Ring, F: NTTField> Vfhe<R, F> {
    /// Creates a new [`Vfhe<R, F>`].
    #[inline]
    pub fn new(lwe_param: LWEParam<R>, rlwe_param: RLWEParam<F>) -> Self {
        Self {
            lwe_param,
            rlwe_param,
        }
    }

    /// Returns the lwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe_param(&self) -> &LWEParam<R> {
        &self.lwe_param
    }

    /// Returns a mutable reference to the lwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe_param_mut(&mut self) -> &mut LWEParam<R> {
        &mut self.lwe_param
    }

    /// Returns the rlwe param of this [`Vfhe<R, F>`].
    pub fn rlwe_param(&self) -> &RLWEParam<F> {
        &self.rlwe_param
    }

    /// Returns a mutable reference to the rlwe param of this [`Vfhe<R, F>`].
    pub fn rlwe_param_mut(&mut self) -> &mut RLWEParam<F> {
        &mut self.rlwe_param
    }

    /// Returns a reference to the public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn public_key(&self) -> &LWEPublicKey<R> {
        self.lwe_param.public_key()
    }

    /// Returns the secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&LWESecretKey<R>> {
        self.lwe_param.secret_key()
    }

    /// Sets the public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: LWEPublicKey<R>) {
        self.lwe_param.set_public_key(public_key)
    }

    /// Sets the secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<LWESecretKey<R>>) {
        self.lwe_param.set_secret_key(secret_key)
    }

    /// encode
    #[inline]
    pub fn encode(&self, value: R::Inner) -> LWEPlaintext<R> {
        self.lwe_param.encode(value)
    }

    /// decode
    #[inline]
    pub fn decode(&self, plaintext: LWEPlaintext<R>) -> R::Inner {
        self.lwe_param.decode(plaintext)
    }
}

impl<R: RandomRing, F: NTTField> Vfhe<R, F> {
    /// generate binary secret key
    #[inline]
    pub fn generate_binary_lwe_sk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        rng: Rng,
    ) -> LWESecretKey<R> {
        self.lwe_param.generate_binary_sk(rng)
    }

    /// generate ternary secret key
    #[inline]
    pub fn generate_ternary_lwe_sk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        rng: Rng,
    ) -> LWESecretKey<R> {
        self.lwe_param.generate_ternary_sk(rng)
    }

    /// generate public key
    pub fn generate_lwe_pk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        sk: &LWESecretKey<R>,
        mut rng: Rng,
    ) -> LWEPublicKey<R> {
        let dis = R::standard_distribution();
        let n = self.lwe_param.n();
        let err = self.lwe_param.err_std_dev();
        let err_dis = R::normal_distribution(0.0, err).unwrap();

        (0..64)
            .map(|_| {
                let a: Vec<R> = dis.sample_iter(&mut rng).take(n).collect();
                let b = dot_product(&a, sk.data()) + err_dis.sample(&mut rng);
                (a, b)
            })
            .map(LWECiphertext::from)
            .collect::<Vec<LWECiphertext<R>>>()
            .into()
    }

    /// encrypt
    pub fn encrypt<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: LWEPlaintext<R>,
        mut rng: Rng,
    ) -> LWECiphertext<R> {
        let n = self.lwe_param.n();
        let err = self.lwe_param.err_std_dev();
        let err_dis = R::normal_distribution(0.0, err).unwrap();

        let c = LWECiphertext::from((
            vec![R::zero(); n],
            plaintext.data() + err_dis.sample(&mut rng),
        ));

        self.lwe_param
            .public_key()
            .data()
            .choose_multiple(&mut rng, 4)
            .fold(c, LWECiphertext::no_boot_add)
    }

    /// decrypt
    pub fn decrypt(&self, ciphertext: &LWECiphertext<R>) -> LWEPlaintext<R> {
        let lwe = ciphertext.data();
        self.lwe_param.secret_key().map_or_else(
            || panic!("Decryption should supply secret key"),
            |sk| LWEPlaintext::new(lwe.b() - dot_product(lwe.a(), sk.data())),
        )
    }
}

impl<R: Ring, F: RandomNTTField> Vfhe<R, F> {
    /// Perform addition
    #[inline]
    pub fn nand(&self, c0: LWECiphertext<R>, c1: &LWECiphertext<R>) -> Self {
        let add = c0.no_boot_add(c1);

        let mut b = add.data().b();

        let q = self.lwe_param().q();
        let big_q = self.rlwe_param().q();
        let big_n = self.rlwe_param().n();

        let mut v = Polynomial::zero_with_coeff_count(big_n);

        let step = self.rlwe_param().n() * 2 / R::cast_into_usize(q);
        let step_r = R::cast_from_usize(step);
        let l = (cast::<u8, <R as Ring>::Inner>(3).unwrap() * q) >> 3;
        let r = (cast::<u8, <R as Ring>::Inner>(7).unwrap() * q) >> 3;
        v.iter_mut().step_by(step).for_each(|a| {
            if (l..r).contains(&b.inner()) {
                *a = F::from(big_q >> 3);
            } else {
                *a = -F::from(big_q >> 3);
            }
            b -= step_r;
        });

        let _acc = RLWE::from(v);
        todo!()
    }
}
