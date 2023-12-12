use algebra::{
    field::Field,
    ring::{RandomRing, Ring},
};
use lattice::LWE;
use rand_distr::Distribution;

use crate::{Ciphertext, Params, PublicKey, SecretKey};

/// fhe scheme
#[derive(Debug, Clone)]
pub struct Vfhe<R: Ring, F: Field> {
    params: Params<R, F>,
    sk: Option<SecretKey<R>>,
    pk: PublicKey<R>,
}

impl<R: Ring, F: Field> Vfhe<R, F> {
    /// Creates a new [`Vfhe<R, F>`].
    #[inline]
    pub fn new(params: Params<R, F>) -> Self {
        Self {
            params,
            sk: None,
            pk: PublicKey::default(),
        }
    }

    /// Returns a reference to the params of this [`Vfhe<R, F>`].
    #[inline]
    pub fn params(&self) -> &Params<R, F> {
        &self.params
    }

    /// Returns the sk of this [`Vfhe<R, F>`].
    #[inline]
    pub fn sk(&self) -> Option<&SecretKey<R>> {
        self.sk.as_ref()
    }

    /// Returns a reference to the pk of this [`Vfhe<R, F>`].
    #[inline]
    pub fn pk(&self) -> &PublicKey<R> {
        &self.pk
    }

    /// Sets the pk of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_pk(&mut self, pk: PublicKey<R>) {
        self.pk = pk;
    }
}

impl<R: RandomRing, F: Field> Vfhe<R, F> {
    /// generate binary secret key
    #[inline]
    pub fn generate_binary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        self.params.lwe().key_gen().generate_binary_sk(rng)
    }

    /// generate ternary secret key
    #[inline]
    pub fn generate_ternary_sk<Rng: rand::Rng + rand::CryptoRng>(&self, rng: Rng) -> SecretKey<R> {
        self.params.lwe().key_gen().generate_ternary_sk(rng)
    }

    /// generate public key
    pub fn generate_pk<Rng: rand::Rng + rand::CryptoRng>(
        &self,
        sk: &SecretKey<R>,
        mut rng: Rng,
    ) -> PublicKey<R> {
        #[inline]
        fn dot_product<R: Ring>(u: &[R], v: &[R]) -> R {
            u.iter()
                .zip(v.iter())
                .fold(R::zero(), |acc, (x, y)| acc + *x * y)
        }

        let dis = R::standard_distribution();
        let n = self.params.lwe().n();
        let err = self.params.lwe().err_std_dev();
        let err_dis = R::normal_distribution(0.0, err).unwrap();

        (0..64)
            .map(|_| {
                let a: Vec<R> = dis.sample_iter(&mut rng).take(n).collect();
                let b = dot_product(&a, sk.data()) + err_dis.sample(&mut rng);
                (a, b)
            })
            .map(LWE::from)
            .map(Ciphertext::from)
            .collect::<Vec<Ciphertext<R>>>()
            .into()
    }
}
