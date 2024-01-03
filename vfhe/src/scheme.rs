use algebra::{Basis, NTTField, NTTPolynomial, Polynomial, RandomNTTField, RandomRing, Ring};
use lattice::{NTTGadgetRLWE, NTTRGSW};
use num_traits::cast;

use crate::{
    functional_bootstrapping::nand_acc, BootstrappingKey, LWECiphertext, LWEParam, LWEPlaintext,
    LWEPublicKey, LWESecretKey, NTTRLWECiphertext, NTTRLWESecretKey, RLWECiphertext, RLWESecretKey,
    RingParam,
};

/// FHE scheme, which contains the parameters for the entire homomorphic encryption
#[derive(Debug, Clone)]
pub struct Vfhe<R: Ring, F: NTTField> {
    /// The parameter for lwe
    lwe: LWEParam<R>,
    /// The parameter for rlwe and rgsw
    rlwe: RingParam<F>,
    /// Modulus value of the lwe, refers to **`q`** in the paper.
    ql: f64,
    /// Modulus value of the rlwe and rgsw, refers to **`Q`** in the paper.
    qr: f64,
    /// Refers to **`2N/q`** in the paper.
    nr2divql: usize,
    /// Bootstrapping key
    bootstrapping_key: BootstrappingKey<F>,
    /// Decompose basis for `Q` used for key switching
    bks: Basis<F>,
    /// bks' powers
    bkss: Vec<F>,
    /// Key switching key
    key_switching_key: Vec<NTTGadgetRLWE<F>>,
}

impl<R: Ring, F: NTTField> Vfhe<R, F> {
    /// Creates a new [`Vfhe<R, F>`].
    pub fn new(
        lwe_param: LWEParam<R>,
        rlwe_param: RingParam<F>,
        key_switching_basis_bits: u32,
    ) -> Self {
        let nr = rlwe_param.n();
        let ql: usize = cast::<<R as Ring>::Inner, usize>(lwe_param.q()).unwrap();

        debug_assert!(ql <= (nr << 1));

        let nr2divql = (nr << 1) / ql;

        let ql = cast::<<R as Ring>::Inner, f64>(lwe_param.q()).unwrap();
        let qr = cast::<<F as Ring>::Inner, f64>(rlwe_param.q()).unwrap();

        let bks = <Basis<F>>::new(key_switching_basis_bits);
        let dks = bks.decompose_len();
        let bf = F::new(bks.basis());

        debug_assert!(bf < F::new(F::modulus_value()));

        let mut bkss = vec![F::zero(); dks];
        let mut temp = F::one();
        bkss.iter_mut().for_each(|v| {
            *v = temp;
            temp *= bf;
        });

        Self {
            lwe: lwe_param,
            rlwe: rlwe_param,
            ql,
            qr,
            nr2divql,
            bootstrapping_key: BootstrappingKey::TFHEBinary(Vec::new()),
            bks,
            bkss,
            key_switching_key: Vec::new(),
        }
    }

    /// Returns the lwe parameter of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe(&self) -> &LWEParam<R> {
        &self.lwe
    }

    /// Returns a mutable reference to the lwe parameter of this [`Vfhe<R, F>`].
    #[inline]
    pub fn lwe_mut(&mut self) -> &mut LWEParam<R> {
        &mut self.lwe
    }

    /// Returns the rlwe parameter of this [`Vfhe<R, F>`].
    #[inline]
    pub fn rlwe(&self) -> &RingParam<F> {
        &self.rlwe
    }

    /// Returns a mutable reference to the rlwe parameter of this [`Vfhe<R, F>`].
    #[inline]
    pub fn rlwe_mut(&mut self) -> &mut RingParam<F> {
        &mut self.rlwe
    }

    /// Returns the **`nr * 2 / ql`** of this [`Vfhe<R, F>`], refers to **`2N/q`** in the paper.
    #[inline]
    pub fn nr2divql(&self) -> usize {
        self.nr2divql
    }

    /// Returns a reference to the LWE public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn public_key(&self) -> &LWEPublicKey<R> {
        self.lwe.public_key()
    }

    /// Returns the LWE secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn secret_key(&self) -> Option<&LWESecretKey<R>> {
        self.lwe.secret_key()
    }

    /// Sets the LWE public key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_public_key(&mut self, public_key: LWEPublicKey<R>) {
        self.lwe.set_public_key(public_key)
    }

    /// Sets the LWE secret key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_secret_key(&mut self, secret_key: Option<LWESecretKey<R>>) {
        self.lwe.set_secret_key(secret_key)
    }

    /// Encodes a value from message space into LWE Plaintext
    #[inline]
    pub fn encode(&self, value: R::Inner) -> LWEPlaintext<R> {
        self.lwe.encode(value)
    }

    /// Decodes a LWE Plaintext into a value of message space
    #[inline]
    pub fn decode(&self, plain: LWEPlaintext<R>) -> R::Inner {
        self.lwe.decode(plain)
    }

    /// Returns the bootstrapping key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn bootstrapping_key(&self) -> &BootstrappingKey<F> {
        &self.bootstrapping_key
    }

    /// Sets the bootstrapping key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_bootstrapping_key(&mut self, bks: BootstrappingKey<F>) {
        self.bootstrapping_key = bks;
    }

    /// Returns the key switching key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn key_switching_key(&self) -> &Vec<NTTGadgetRLWE<F>> {
        &self.key_switching_key
    }

    /// Sets the key switching key of this [`Vfhe<R, F>`].
    #[inline]
    pub fn set_key_switching_key(&mut self, ksk: Vec<NTTGadgetRLWE<F>>) {
        self.key_switching_key = ksk;
    }

    /// Returns the ql of this [`Vfhe<R, F>`],  refers to **`q`** in the paper.
    #[inline]
    pub fn ql(&self) -> f64 {
        self.ql
    }

    /// Returns the qr of this [`Vfhe<R, F>`], refers to **`Q`** in the paper.
    #[inline]
    pub fn qr(&self) -> f64 {
        self.qr
    }

    /// Decrypts the [`LWECiphertext`] back to [`LWEPlaintext`]
    #[inline]
    pub fn decrypt(&self, cipher: &LWECiphertext<R>) -> LWEPlaintext<R> {
        self.lwe.decrypt(cipher)
    }
}

impl<R: RandomRing, F: NTTField> Vfhe<R, F> {
    /// Generates [`LWESecretKey<R>`] randomly.
    #[inline]
    pub fn generate_lwe_sk<Rng>(&self, rng: Rng) -> LWESecretKey<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.generate_sk(rng)
    }

    /// Generates [`LWEPublicKey<R>`] randomly.
    #[inline]
    pub fn generate_lwe_pk<Rng>(&self, sk: &LWESecretKey<R>, rng: Rng) -> LWEPublicKey<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.generate_pk(sk, rng)
    }

    /// Encrypts [`LWEPlaintext<R>`] into [`LWECiphertext<R>`] by [`LWEPublicKey<R>`].
    #[inline]
    pub fn encrypt_by_pk<Rng>(&self, plain: LWEPlaintext<R>, rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.encrypt_by_pk(plain, rng)
    }

    /// Encrypts [`LWEPlaintext<R>`] into [`LWECiphertext<R>`] by [`LWESecretKey<R>`].
    #[inline]
    pub fn encrypt_by_sk<Rng>(&self, plain: LWEPlaintext<R>, rng: Rng) -> LWECiphertext<R>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.lwe.encrypt_by_sk(plain, rng)
    }
}

impl<R: Ring, F: RandomNTTField> Vfhe<R, F> {
    /// Generates RLWE Secret Key[`RLWESecretKey<F>`].
    #[inline]
    pub fn generate_rlwe_sk<Rng>(&self, rng: Rng) -> RLWESecretKey<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.rlwe.generate_sk(rng)
    }

    /// Generates RLWE Public Key [`RLWEPublicKey<F>`].
    #[inline]
    pub fn generate_rlwe_pk<Rng>(
        &self,
        sk: &NTTRLWESecretKey<F>,
        rng: Rng,
    ) -> crate::RLWEPublicKey<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        self.rlwe.generate_pk(sk, rng)
    }

    /// Generates bootstrapping key.
    pub fn generate_bootstrapping_key<Rng>(
        &self,
        lwe_sk: &LWESecretKey<R>,
        rlwe_sk: &NTTRLWESecretKey<F>,
        mut rng: Rng,
    ) -> BootstrappingKey<F>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        match self.lwe.secret_key_distribution() {
            crate::LWESecretKeyDistribution::Binary => {
                let bks = lwe_sk
                    .iter()
                    .map(|&s| {
                        let mut bk = self.rlwe.rgsw_zero_by_sk(&mut rng, rlwe_sk);
                        if s.is_one() {
                            self.rlwe.rgsw_zero_to_one(&mut bk);
                        }
                        NTTRGSW::from(bk)
                    })
                    .collect();
                BootstrappingKey::binary_bootstrapping_key(bks)
            }
            crate::LWESecretKeyDistribution::Ternary => {
                let bks = lwe_sk
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
                        (NTTRGSW::from(u0), NTTRGSW::from(u1))
                    })
                    .collect();
                BootstrappingKey::ternary_bootstrapping_key(bks)
            }
        }
    }

    /// Generates key switching key.
    pub fn generate_key_switching_key<Rng>(
        &self,
        rlwe_sk: &RLWESecretKey<F>,
        lwe_sk: &LWESecretKey<R>,
        mut rng: Rng,
    ) -> Vec<NTTGadgetRLWE<F>>
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let nl = self.lwe.n();
        let bks = self.bks;
        let bkss = &self.bkss;
        let chi = self.rlwe.error_distribution();
        let s = <Polynomial<F>>::new(
            lwe_sk
                .iter()
                .map(|&v| {
                    if v.is_one() {
                        F::ONE
                    } else if v == R::NEG_ONE {
                        F::NEG_ONE
                    } else {
                        F::ZERO
                    }
                })
                .collect(),
        );

        let sn = s.to_ntt_polynomial();

        rlwe_sk
            .as_slice()
            .chunks(nl)
            .map(|z| {
                let nzp = Polynomial::from_slice(z).to_ntt_polynomial();
                let k_i = bkss
                    .iter()
                    .map(|&b_i| {
                        let a = <NTTPolynomial<F>>::random(nl, &mut rng);
                        let e = <Polynomial<F>>::random_with_dis(nl, &mut rng, chi);

                        let b = &a * &sn + nzp.mul_scalar(b_i.inner()) + e.to_ntt_polynomial();

                        NTTRLWECiphertext::new(a, b)
                    })
                    .collect::<Vec<NTTRLWECiphertext<F>>>();
                NTTGadgetRLWE::new(k_i, bks)
            })
            .collect()
    }

    /// Performs nand operation.
    pub fn nand(&self, c0: LWECiphertext<R>, c1: &LWECiphertext<R>) -> LWECiphertext<F> {
        let add = c0.add_component_wise(c1);

        let b = add.b();

        let nl = self.lwe.n();
        let nr = self.rlwe.n();

        let acc: RLWECiphertext<F> = nand_acc(b, nr, self.nr2divql);
        let acc = self
            .bootstrapping_key
            .bootstrapping(acc, add.a(), nr, self.nr2divql);

        let mut extract = acc.extract_lwe();
        *extract.b_mut() += F::Q_DIV_8;

        let key_switching = extract.key_switch(&self.key_switching_key, nl);

        debug_assert!(key_switching
            .a()
            .iter()
            .all(|&v| v.inner() < F::modulus_value()));
        debug_assert!(key_switching.b().inner() < F::modulus_value());

        key_switching
    }
}
