use std::sync::Arc;

use algebra::{
    integer::UnsignedInteger,
    polynomial::FieldPolynomial,
    reduce::{ModulusValue, ReduceAddAssign, RingReduce},
    Field, NttField,
};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign, lwe_modulus_switch_inplace, BlindRotationKey,
    LweCiphertext, LweKeySwitchingKeyRlweMode, LweSecretKey, LweSecretKeyType,
    NonPowOf2LweKeySwitchingKey, PowOf2LweKeySwitchingKey, RingSecretKeyType,
};
use rand::{CryptoRng, Rng};

use crate::{parameter::Steps, BooleanFheParameters, LookUpTable, SecretKeyPack};

/// A enum type for different key switching purposes.
#[derive(Clone)]
pub enum KeySwitchingKey<C: UnsignedInteger, Q: NttField> {
    /// The key switching is based on rlwe multiply with gadget rlwe.
    PowOf2DimensionLwe(LweKeySwitchingKeyRlweMode<Q>),
    /// The key switching is based on LWE constant multiplication.
    PowOf2ModulusLwe(PowOf2LweKeySwitchingKey<C>),
    /// The key switching is based on non power of 2 modulus LWE.
    NonPowOf2ModulusLwe(NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT>),
    /// No key switching.
    None,
}

impl<C: UnsignedInteger, Q: NttField> KeySwitchingKey<C, Q> {
    /// Returns an `Option` containing a reference to the
    /// `LweKeySwitchingKeyRlweMode<Q>` if the key is in `PowOf2DimensionLwe` mode, otherwise `None`.
    #[inline]
    pub fn as_pow_of_2_dimension_lwe(&self) -> Option<&LweKeySwitchingKeyRlweMode<Q>> {
        if let Self::PowOf2DimensionLwe(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Returns an `Option` containing a reference to the
    /// `PowOf2LweKeySwitchingKey<C>` if the key is in `PowOf2ModulusLwe` mode, otherwise `None`.
    #[inline]
    pub fn as_pow_of_2_modulus_lwe(&self) -> Option<&PowOf2LweKeySwitchingKey<C>> {
        if let Self::PowOf2ModulusLwe(v) = self {
            Some(v)
        } else {
            None
        }
    }

    /// Attempts to convert the key into an
    /// `LweKeySwitchingKeyRlweMode<Q>`. Returns `Ok` with the key if successful, otherwise returns
    /// `Err` with the original key.
    #[inline]
    pub fn try_into_pow_of_2_dimension_lwe(self) -> Result<LweKeySwitchingKeyRlweMode<Q>, Self> {
        if let Self::PowOf2DimensionLwe(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    /// Attempts to convert the key into a
    /// `PowOf2LweKeySwitchingKey<C>`. Returns `Ok` with the key if successful, otherwise returns
    /// `Err` with the original key.
    #[inline]
    pub fn try_into_pow_of_2_modulus_lwe(self) -> Result<PowOf2LweKeySwitchingKey<C>, Self> {
        if let Self::PowOf2ModulusLwe(v) = self {
            Ok(v)
        } else {
            Err(self)
        }
    }

    /// Returns an `Option` containing a reference to the
    /// `NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT>` if the key is in `NonPowOf2ModulusLwe` mode,
    /// otherwise `None`.
    #[inline]
    pub fn as_non_pow_of_2_modulus_lwe(
        &self,
    ) -> Option<&NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT>> {
        if let Self::NonPowOf2ModulusLwe(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

/// The evaluator of the homomorphic encryption scheme.
#[derive(Clone)]
pub struct EvaluationKey<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> {
    /// Blind rotation key.
    blind_rotation_key: BlindRotationKey<Q>,
    /// Key switching key.
    key_switching_key: KeySwitchingKey<C, Q>,
    /// The parameters of the fully homomorphic encryption scheme.
    parameters: BooleanFheParameters<C, LweModulus, Q>,
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> EvaluationKey<C, LweModulus, Q> {
    /// Returns a reference to the parameters of this [`EvaluationKey<C, LweModulus, Q>`].
    #[inline]
    pub fn parameters(&self) -> &BooleanFheParameters<C, LweModulus, Q> {
        &self.parameters
    }

    /// Creates a new [`EvaluationKey`] from the given [`SecretKeyPack`].
    #[inline]
    pub fn new<R>(secret_key_pack: &SecretKeyPack<C, LweModulus, Q>, rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let parameters = secret_key_pack.parameters();

        let blind_rotation_key = BlindRotationKey::generate(
            secret_key_pack.lwe_secret_key(),
            secret_key_pack.ntt_rlwe_secret_key(),
            parameters.blind_rotation_basis(),
            parameters.ring_noise_distribution(),
            Arc::clone(secret_key_pack.ntt_table()),
            rng,
        );

        let s_in = secret_key_pack.rlwe_secret_key();
        let s_out = secret_key_pack.lwe_secret_key();
        let key_switching_key = match parameters.steps() {
            Steps::BrMsKs => {
                let lwe_cipher_modulus_minus_one = parameters.lwe_cipher_modulus_minus_one();
                let s_in = LweSecretKey::from_rlwe_secret_key(s_in, lwe_cipher_modulus_minus_one);

                let ksk = PowOf2LweKeySwitchingKey::generate(
                    &s_in,
                    s_out,
                    parameters.key_switching_params(),
                    parameters.lwe_cipher_modulus(),
                    rng,
                );
                KeySwitchingKey::PowOf2ModulusLwe(ksk)
            }
            Steps::BrKsRlevMs => {
                let ksk: LweKeySwitchingKeyRlweMode<Q> = LweKeySwitchingKeyRlweMode::generate(
                    s_in,
                    s_out,
                    parameters.key_switching_params(),
                    Arc::clone(secret_key_pack.ntt_table()),
                    rng,
                );
                KeySwitchingKey::PowOf2DimensionLwe(ksk)
            }
            Steps::BrKsLevMs => {
                let distr = match s_in.distr() {
                    RingSecretKeyType::Binary => LweSecretKeyType::Binary,
                    RingSecretKeyType::Ternary => LweSecretKeyType::Ternary,
                    RingSecretKeyType::Gaussian => panic!("Not support"),
                };
                let s_in = LweSecretKey::new(s_in.as_slice().to_vec(), distr);

                let ksk: NonPowOf2LweKeySwitchingKey<<Q as Field>::ValueT> =
                    NonPowOf2LweKeySwitchingKey::generate(
                        &s_in,
                        s_out,
                        parameters.key_switching_params(),
                        Q::MODULUS,
                        rng,
                    );
                KeySwitchingKey::NonPowOf2ModulusLwe(ksk)
            }
            Steps::BrMs => KeySwitchingKey::None,
        };

        Self {
            blind_rotation_key,
            key_switching_key,
            parameters: *parameters,
        }
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and lookup table `lut`.
    pub fn bootstrap(&self, mut c: LweCiphertext<C>, lut: FieldPolynomial<Q>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let twice_ring_dimension_value =
            C::try_from(parameters.ring_dimension() << 1).ok().unwrap();

        // modulus switch q -> 2N
        lwe_modulus_switch_assign(
            &mut c,
            parameters.lwe_cipher_modulus_value(),
            twice_ring_dimension_value,
        );

        // blind rotation
        let mut acc = self.blind_rotation_key.blind_rotate(lut, &c);

        <Q as Field>::MODULUS.reduce_add_assign(&mut acc.b_mut()[0], Q::MODULUS_VALUE >> 3u32);

        // key switch and modulus switch (N, Q) -> (n, q)
        match parameters.steps() {
            Steps::BrMsKs => {
                let acc = acc.extract_lwe_locally();
                let cipher = lwe_modulus_switch(
                    &acc,
                    parameters.ring_modulus(),
                    parameters.lwe_cipher_modulus_value(),
                );

                let ksk = match self.key_switching_key {
                    KeySwitchingKey::PowOf2ModulusLwe(ref ksk) => ksk,
                    _ => panic!("Unable to get the corresponding key switching key!"),
                };

                c = ksk.key_switch(&cipher, parameters.lwe_cipher_modulus());
            }
            Steps::BrKsRlevMs => {
                let ksk = match self.key_switching_key {
                    KeySwitchingKey::PowOf2DimensionLwe(ref ksk) => ksk,
                    _ => panic!("Unable to get the corresponding key switching key!"),
                };

                let key_switched = ksk.key_switch_for_rlwe(acc);

                lwe_modulus_switch_inplace(
                    key_switched,
                    Q::MODULUS_VALUE,
                    parameters.lwe_cipher_modulus_value(),
                    &mut c,
                );
            }
            Steps::BrKsLevMs => {
                let acc = acc.extract_lwe_locally();
                let ksk = self
                    .key_switching_key
                    .as_non_pow_of_2_modulus_lwe()
                    .unwrap();
                let temp = ksk.key_switch(&acc, Q::MODULUS);

                c = lwe_modulus_switch(
                    &temp,
                    parameters.ring_modulus(),
                    parameters.lwe_cipher_modulus_value(),
                );
            }
            Steps::BrMs => {
                let lwe = acc.extract_lwe_locally();

                lwe_modulus_switch_inplace(
                    lwe,
                    Q::MODULUS_VALUE,
                    parameters.lwe_cipher_modulus_value(),
                    &mut c,
                );
            }
        }

        c
    }
}

/// Evaluator
#[derive(Clone)]
pub struct Evaluator<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> {
    ek: EvaluationKey<C, LweModulus, Q>,
}

impl<C: UnsignedInteger, LweModulus: RingReduce<C>, Q: NttField> Evaluator<C, LweModulus, Q> {
    /// Create a new instance.
    #[inline]
    pub fn new<R: Rng + CryptoRng>(sk: &SecretKeyPack<C, LweModulus, Q>, rng: &mut R) -> Self {
        Self {
            ek: EvaluationKey::new(sk, rng),
        }
    }

    /// Returns a reference to the parameters of this [`Evaluator<F>`].
    #[inline]
    pub fn parameters(&self) -> &BooleanFheParameters<C, LweModulus, Q> {
        self.ek.parameters()
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and lookup table `lut`.
    #[inline]
    pub fn bootstrap(&self, c: LweCiphertext<C>, lut: FieldPolynomial<Q>) -> LweCiphertext<C> {
        self.ek.bootstrap(c, lut)
    }

    /// Performs the homomorphic not operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c`, with message `true`(resp. `false`).
    /// * Output: ciphertext with message `false`(resp. `true`).
    ///
    /// Link: <https://eprint.iacr.org/2020/086>
    pub fn not(&self, c: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let mut neg = c.neg_reduce(cipher_modulus);

        match parameters.lwe_cipher_modulus_value() {
            ModulusValue::Native => {
                cipher_modulus.reduce_add_assign(neg.b_mut(), C::ONE << (C::BITS - 2))
            }
            ModulusValue::PowerOf2(q) | ModulusValue::Prime(q) | ModulusValue::Others(q) => {
                cipher_modulus.reduce_add_assign(neg.b_mut(), q >> 2u32)
            }
        }

        neg
    }

    /// Performs the homomorphic nand operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a and b)`.
    pub fn nand(&self, c0: &LweCiphertext<C>, c1: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, cipher_modulus);

        let lut = nand_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic and operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a and b`.
    pub fn and(&self, c0: &LweCiphertext<C>, c1: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, cipher_modulus);

        let lut = and_majority_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic or operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a or b`.
    pub fn or(&self, c0: &LweCiphertext<C>, c1: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, cipher_modulus);

        let lut = or_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic nor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a or b)`.
    pub fn nor(&self, c0: &LweCiphertext<C>, c1: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, cipher_modulus);

        let lut = nor_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic xor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a xor b`.
    pub fn xor(&self, c0: &LweCiphertext<C>, c1: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, cipher_modulus);
        sub.mul_scalar_reduce_assign(C::ONE + C::ONE, cipher_modulus);

        let lut = xor_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(sub, lut)
    }

    /// Performs the homomorphic xnor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a xor b)`.
    pub fn xnor(&self, c0: &LweCiphertext<C>, c1: &LweCiphertext<C>) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, cipher_modulus);
        sub.mul_scalar_reduce_assign(C::ONE + C::ONE, cipher_modulus);

        let lut = xnor_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(sub, lut)
    }

    /// Performs the homomorphic majority operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Input: ciphertext `c2`, with message `c`.
    /// * Output: ciphertext with message `(a & b) | (b & c) | (a & c)`.
    ///   If there are two or three `true`(resp. `false`) in `a`, `b` and `c`, it will return `true`(resp. `false`).
    pub fn majority(
        &self,
        c0: &LweCiphertext<C>,
        c1: &LweCiphertext<C>,
        c2: &LweCiphertext<C>,
    ) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let mut add = c0.add_reduce_component_wise_ref(c1, cipher_modulus);
        add.add_reduce_assign_component_wise(c2, cipher_modulus);

        let lut = and_majority_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic mux operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Input: ciphertext `c2`, with message `c`.
    /// * Output: ciphertext with message `if a {b} else {c}`.
    ///   If `a` is `true`, it will return `b`. If `a` is `false`, it will return `c`.
    pub fn mux(
        &self,
        c0: &LweCiphertext<C>,
        c1: &LweCiphertext<C>,
        c2: &LweCiphertext<C>,
    ) -> LweCiphertext<C> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.lwe_cipher_modulus();

        let not_c0 = self.not(c0);

        let (mut t0, t1) = rayon::join(|| self.and(c0, c1), || self.and(&not_c0, c2));

        // (a & b) | (!a & c)
        t0.add_reduce_assign_component_wise(&t1, cipher_modulus);

        let lut = or_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus().as_into(),
        );

        self.bootstrap(t0, lut)
    }
}

/// init lut for bootstrapping which performs homomorphic `nand`.
fn nand_lut<F>(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<F>
where
    F: NttField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = q >> 3u32;
    let neg_q_div_8 = q - q_div_8;

    let log_plain_modulus = plain_modulus.trailing_zeros();

    // 0,1 -> q/8
    // 2,3 -> -q/8
    [q_div_8, q_div_8, neg_q_div_8, neg_q_div_8].negacyclic_lut(rlwe_dimension, log_plain_modulus)
}

/// init lut for bootstrapping which performs homomorphic `and` or `majority`.
fn and_majority_lut<F>(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<F>
where
    F: NttField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = q >> 3u32;
    let neg_q_div_8 = q - q_div_8;
    let log_plain_modulus = plain_modulus.trailing_zeros();

    // 0,1 -> -q/8
    // 2,3 -> q/8
    [neg_q_div_8, neg_q_div_8, q_div_8, q_div_8].negacyclic_lut(rlwe_dimension, log_plain_modulus)
}

/// init lut for bootstrapping which performs homomorphic `or`.
fn or_lut<F>(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<F>
where
    F: NttField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = q >> 3u32;
    let neg_q_div_8 = q - q_div_8;
    let log_plain_modulus = plain_modulus.trailing_zeros();

    // 1,2 -> q/8
    // 0,3 -> -q/8
    [neg_q_div_8, q_div_8, q_div_8, neg_q_div_8].negacyclic_lut(rlwe_dimension, log_plain_modulus)
}

/// init lut for bootstrapping which performs homomorphic `nor`.
fn nor_lut<F>(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<F>
where
    F: NttField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = q >> 3u32;
    let neg_q_div_8 = q - q_div_8;
    let log_plain_modulus = plain_modulus.trailing_zeros();

    // 1,2 -> -q/8
    // 0,3 -> q/8
    [q_div_8, neg_q_div_8, neg_q_div_8, q_div_8].negacyclic_lut(rlwe_dimension, log_plain_modulus)
}

/// init lut for bootstrapping which performs homomorphic `xor`.
fn xor_lut<F>(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<F>
where
    F: NttField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = q >> 3u32;
    let neg_q_div_8 = q - q_div_8;
    let log_plain_modulus = plain_modulus.trailing_zeros();

    // 0 -> -q/8
    // 2 -> q/8
    [neg_q_div_8, q_div_8].negacyclic_lut(rlwe_dimension, log_plain_modulus - 1)
}

/// init lut for bootstrapping which performs homomorphic `xor`.
fn xnor_lut<F>(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<F>
where
    F: NttField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = q >> 3u32;
    let neg_q_div_8 = q - q_div_8;
    let log_plain_modulus = plain_modulus.trailing_zeros();

    // 0 -> q/8
    // 2 -> -q/8
    [q_div_8, neg_q_div_8].negacyclic_lut(rlwe_dimension, log_plain_modulus - 1)
}
