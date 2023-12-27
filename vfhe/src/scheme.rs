use algebra::{
    field::{NTTField, RandomNTTField},
    polynomial::Polynomial,
    ring::{RandomRing, Ring},
};
use lattice::{GadgetRLWE, LWE, RLWE};
use num_traits::cast;

use crate::{
    functional_bootstrapping::nand_acc, BootstrappingKey, LWECiphertext, LWEParam, LWEPlaintext,
    LWEPublicKey, LWESecretKey, RLWESecretKey, RingParam,
};

/// fhe scheme
#[derive(Debug, Clone)]
pub struct Vfhe<R: Ring, F: NTTField> {
    lwe: LWEParam<R>,
    rlwe: RingParam<F>,
    ql: f64,
    qr: f64,
    nr2divq: usize,
    bks: BootstrappingKey<F>,
    ksk: Vec<GadgetRLWE<F>>,
}

impl<R: Ring, F: NTTField> Vfhe<R, F> {
    /// Creates a new [`Vfhe<R, F>`].
    #[inline]
    pub fn new(lwe_param: LWEParam<R>, rlwe_param: RingParam<F>) -> Self {
        let n = rlwe_param.n();
        let q = R::new(lwe_param.q()).cast_into_usize();
        let nr2divq = (n << 1) / q;

        let ql = cast::<<R as Ring>::Inner, f64>(lwe_param.q()).unwrap();
        let qr = cast::<<F as Ring>::Inner, f64>(rlwe_param.q()).unwrap();

        Self {
            lwe: lwe_param,
            rlwe: rlwe_param,
            ql,
            qr,
            nr2divq,
            bks: BootstrappingKey::TFHEBinary(Vec::new()),
            ksk: Vec::new(),
        }
    }

    /// Returns the lwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe(&self) -> &LWEParam<R> {
        &self.lwe
    }

    /// Returns a mutable reference to the lwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe_mut(&mut self) -> &mut LWEParam<R> {
        &mut self.lwe
    }

    /// Returns the rlwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn rlwe(&self) -> &RingParam<F> {
        &self.rlwe
    }

    /// Returns a mutable reference to the rlwe param of this [`Vfhe<R, F>`].
    #[inline]
    pub fn rlwe_mut(&mut self) -> &mut RingParam<F> {
        &mut self.rlwe
    }

    /// Returns the l2divq of this [`Vfhe<R, F>`].
    #[inline]
    pub fn l2divq(&self) -> usize {
        self.nr2divq
    }

    /// Returns a reference to the public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn public_key(&self) -> &LWEPublicKey<R> {
        self.lwe.public_key()
    }

    /// Returns the secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&LWESecretKey<R>> {
        self.lwe.secret_key()
    }

    /// Sets the public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: LWEPublicKey<R>) {
        self.lwe.set_public_key(public_key)
    }

    /// Sets the secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<LWESecretKey<R>>) {
        self.lwe.set_secret_key(secret_key)
    }

    /// encode
    #[inline]
    pub fn encode(&self, value: R::Inner) -> LWEPlaintext<R> {
        self.lwe.encode(value)
    }

    /// decode
    #[inline]
    pub fn decode(&self, plaintext: LWEPlaintext<R>) -> R::Inner {
        self.lwe.decode(plaintext)
    }

    /// Returns the bks of this [`Vfhe<R, F>`].
    #[inline]
    pub fn bks(&self) -> &BootstrappingKey<F> {
        &self.bks
    }

    /// Sets the bks of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_bks(&mut self, bks: BootstrappingKey<F>) {
        self.bks = bks;
    }

    /// Returns the ksk of this [`Vfhe<R, F>`].
    pub fn ksk(&self) -> &Vec<GadgetRLWE<F>> {
        &self.ksk
    }

    /// Sets the ksk of this [`Vfhe<R, F>`].
    pub fn set_ksk(&mut self, ksk: Vec<GadgetRLWE<F>>) {
        self.ksk = ksk;
    }
}

impl<R: RandomRing, F: NTTField> Vfhe<R, F> {
    /// generate secret key
    #[inline]
    pub fn generate_lwe_sk<Rng>(&self, rng: Rng) -> LWESecretKey<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.generate_sk(rng)
    }

    /// generate public key
    #[inline]
    pub fn generate_lwe_pk<Rng>(&self, sk: &LWESecretKey<R>, rng: Rng) -> LWEPublicKey<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.generate_pk(sk, rng)
    }

    /// encrypt
    #[inline]
    pub fn encrypt_by_pk<Rng>(&self, plain: LWEPlaintext<R>, rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.encrypt_by_pk(plain, rng)
    }

    /// encrypt
    #[inline]
    pub fn encrypt_by_sk<Rng>(&self, plain: LWEPlaintext<R>, rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.encrypt_by_sk(plain, rng)
    }

    /// decrypt
    #[inline]
    pub fn decrypt(&self, cipher: &LWECiphertext<R>) -> LWEPlaintext<R> {
        self.lwe.decrypt(cipher)
    }
}

impl<R: Ring, F: RandomNTTField> Vfhe<R, F> {
    /// generate bootstrapping key
    pub fn generate_bootstrapping_key(&self) -> BootstrappingKey<F> {
        let rlwe_sk = self.rlwe.secret_key().unwrap();
        let mut rng = rand::thread_rng();
        match self.secret_key() {
            Some(sk) => match self.lwe.secret_key_distribution() {
                crate::LWESecretKeyDistribution::Binary => {
                    let bks = sk
                        .iter()
                        .map(|&s| {
                            let mut bk = self.rlwe.rgsw_zero_by_sk(&mut rng, rlwe_sk);
                            if s.is_one() {
                                self.rlwe.rgsw_zero_to_one(&mut bk);
                            }
                            bk
                        })
                        .collect();
                    BootstrappingKey::binary_bootstrapping_key(bks)
                }
                crate::LWESecretKeyDistribution::Ternary => {
                    let bks = sk
                        .iter()
                        .map(|&s| {
                            let mut u0 = self.rlwe.rgsw_zero_by_sk(&mut rng, rlwe_sk);
                            let mut u1 = self.rlwe.rgsw_zero_by_sk(&mut rng, rlwe_sk);
                            if s.is_one() {
                                self.rlwe.rgsw_zero_to_one(&mut u0);
                            } else if s.is_zero() {
                                self.rlwe.rgsw_zero_to_one(&mut u0);
                                self.rlwe.rgsw_zero_to_one(&mut u1);
                            } else {
                                self.rlwe.rgsw_zero_to_one(&mut u1);
                            }
                            (u0, u1)
                        })
                        .collect();
                    BootstrappingKey::ternary_bootstrapping_key(bks)
                }
                crate::LWESecretKeyDistribution::Gaussian => todo!(),
            },
            None => panic!("generate bootstrapping key should supply secret key"),
        }
    }

    /// Perform addition
    pub fn nand(&self, c0: LWE<R>, c1: &LWE<R>) -> LWE<R> {
        let add = c0.add_component_wise(c1);

        let b = add.b();

        let nl = self.lwe.n();
        let ql = self.lwe.q();
        let nr = self.rlwe.n();
        let qr = self.rlwe.q();

        let acc: RLWE<F> = nand_acc(b, ql, nr, qr, self.nr2divq);
        let acc = self.bks.bootstrapping(acc, add.a(), nr, self.nr2divq);

        let mut extract = acc.extract_lwe();
        *extract.b_mut() += F::new(qr >> 3);

        // {
        //     let r =
        //         extract.b() - dot_product(extract.a(), self.rlwe.secret_key().unwrap().as_ref());
        //     let r = R::from_f64((r.as_f64() * self.ql / self.qr).floor());
        //     dbg!(r);
        //     let dec = self.decode(r);
        //     dbg!(dec);
        // }

        let key_switching = extract.key_switch(&self.ksk, nl);

        // {
        //     let sk: Vec<F> = self
        //         .secret_key()
        //         .unwrap()
        //         .iter()
        //         .map(|&v| F::from_f64(v.as_f64()))
        //         .collect();
        //     let r = key_switching.b() - dot_product(key_switching.a(), &sk);
        //     let r = R::from_f64((r.as_f64() * self.ql / self.qr).floor());
        //     dbg!(r);
        //     let dec = self.decode(r);
        //     dbg!(dec);
        // }

        key_switching.modulus_switch(self.ql, self.qr)
    }

    /// generate key_switching key
    pub fn generate_key_switching_key<Rng>(
        &self,
        rlwe_sk: &RLWESecretKey<F>,
        lwe_sk: &LWESecretKey<R>,
        mut rng: Rng,
    ) -> Vec<GadgetRLWE<F>>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let nl = lwe_sk.len();
        let bg = self.rlwe.bg();
        let bgs = self.rlwe.bgs();
        let chi = self.rlwe.error_distribution();

        let s = <Polynomial<F>>::new(lwe_sk.iter().map(|v| F::from_f64(v.as_f64())).collect());

        rlwe_sk
            .as_slice()
            .chunks(nl)
            .map(|z| {
                let k_i = bgs
                    .iter()
                    .map(|&b_i| {
                        let a = <Polynomial<F>>::random(nl, &mut rng);
                        let e = <Polynomial<F>>::random_with_dis(nl, &mut rng, chi);

                        let b = &a * &s + Polynomial::from_slice(z).mul_scalar(b_i.inner()) + e;

                        RLWE::new(a, b)
                    })
                    .collect::<Vec<RLWE<F>>>();
                GadgetRLWE::new(k_i, bg)
            })
            .collect()
    }
}
