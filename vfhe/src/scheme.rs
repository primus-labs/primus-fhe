use std::marker::PhantomData;

use algebra::{
    field::Field,
    ring::{RandomRing, Ring},
};
use lattice::dot_product;
use rand::seq::SliceRandom;
use rand_distr::Distribution;

use crate::{Ciphertext, LweParam, Plaintext, PublicKey, SecretKey};

/// fhe scheme
#[derive(Debug, Clone)]
pub struct Vfhe<R: Ring, F: Field> {
    lwe_param: LweParam<R>,
    marker: PhantomData<F>,
}

impl<R: Ring, F: Field> Vfhe<R, F> {
    /// Creates a new [`Vfhe<R, F>`].
    #[inline]
    pub fn new(lwe_param: LweParam<R>) -> Self {
        Self {
            lwe_param,
            marker: PhantomData,
        }
    }

    /// Returns the lwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe_param(&self) -> &LweParam<R> {
        &self.lwe_param
    }

    /// Returns a mutable reference to the lwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe_param_mut(&mut self) -> &mut LweParam<R> {
        &mut self.lwe_param
    }

    /// Returns a reference to the public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn public_key(&self) -> &PublicKey<R> {
        self.lwe_param.public_key()
    }

    /// Returns the secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&SecretKey<R>> {
        self.lwe_param.secret_key()
    }

    /// Sets the public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: PublicKey<R>) {
        self.lwe_param.set_public_key(public_key)
    }

    /// Sets the secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<SecretKey<R>>) {
        self.lwe_param.set_secret_key(secret_key)
    }

    /// encode
    #[inline]
    pub fn encode(&self, value: R::Inner) -> Plaintext<R> {
        self.lwe_param.encode(value)
    }

    /// decode
    #[inline]
    pub fn decode(&self, plaintext: Plaintext<R>) -> R::Inner {
        self.lwe_param.decode(plaintext)
    }
}

impl<R: RandomRing, F: Field> Vfhe<R, F> {
    /// generate binary secret key
    #[inline]
    pub fn generate_binary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        self.lwe_param.generate_binary_sk(rng)
    }

    /// generate ternary secret key
    #[inline]
    pub fn generate_ternary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        self.lwe_param.generate_ternary_sk(rng)
    }

    /// generate public key
    pub fn generate_pk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        sk: &SecretKey<R>,
        mut rng: Rng,
    ) -> PublicKey<R> {
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
            .map(Ciphertext::from)
            .collect::<Vec<Ciphertext<R>>>()
            .into()
    }

    /// encrypt
    pub fn encrypt<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        plaintext: Plaintext<R>,
        mut rng: Rng,
    ) -> Ciphertext<R> {
        let n = self.lwe_param.n();
        let err = self.lwe_param.err_std_dev();
        let err_dis = R::normal_distribution(0.0, err).unwrap();

        let c = Ciphertext::from((
            vec![R::zero(); n],
            plaintext.data() + err_dis.sample(&mut rng),
        ));

        self.lwe_param
            .public_key()
            .data()
            .choose_multiple(&mut rng, 4)
            .fold(c, |acc, pk| acc.no_boot_add(pk))
    }

    /// decrypt
    pub fn decrypt(&self, ciphertext: &Ciphertext<R>) -> Plaintext<R> {
        let lwe = ciphertext.data();
        match self.lwe_param.secret_key() {
            Some(sk) => Plaintext::new(lwe.b() - dot_product(lwe.a(), sk.data())),
            None => panic!("Decryption should supply secret key"),
        }
    }
}
