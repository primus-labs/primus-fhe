use algebra::{NTTField, Polynomial};
use fhe_core::{
    lwe_modulus_switch, lwe_modulus_switch_assign_between_modulus, lwe_modulus_switch_inplace,
    BlindRotationKey, KeySwitchingKeyEnum, KeySwitchingLWEKey, KeySwitchingRLWEKey, LWECiphertext,
    LWEModulusType, Parameters, ProcessType, SecretKeyPack, Steps,
};

/// The evaluator of the homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct EvaluationKey<C: LWEModulusType, Q: NTTField> {
    /// Blind rotation key.
    blind_rotation_key: BlindRotationKey<Q>,
    /// Key switching key.
    key_switching_key: KeySwitchingKeyEnum<C, Q>,
    /// The parameters of the fully homomorphic encryption scheme.
    parameters: Parameters<C, Q>,
}

impl<C: LWEModulusType, Q: NTTField> EvaluationKey<C, Q> {
    /// Returns the parameters of this [`EvaluationKey<F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<C, Q> {
        &self.parameters
    }

    /// Creates a new [`EvaluationKey`] from the given [`SecretKeyPack`].
    pub fn new(secret_key_pack: &SecretKeyPack<C, Q>) -> Self {
        let parameters = secret_key_pack.parameters();

        let blind_rotation_key = BlindRotationKey::generate(secret_key_pack);

        let key_switching_key = match parameters.steps() {
            Steps::BrMsKs => {
                KeySwitchingKeyEnum::LWE(KeySwitchingLWEKey::generate(secret_key_pack))
            }
            Steps::BrKsMs => {
                KeySwitchingKeyEnum::RLWE(KeySwitchingRLWEKey::generate(secret_key_pack))
            }
            Steps::BrMs => KeySwitchingKeyEnum::None,
        };

        Self {
            blind_rotation_key,
            key_switching_key,
            parameters: *parameters,
        }
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and lookup table `lut`.
    pub fn bootstrap(&self, mut c: LWECiphertext<C>, lut: Polynomial<Q>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let pre = parameters.process_before_blind_rotation();

        match pre.process() {
            ProcessType::ModulusSwitch => {
                lwe_modulus_switch_assign_between_modulus(
                    &mut c,
                    parameters.lwe_cipher_modulus_value(),
                    pre.twice_ring_dimension_value(),
                );
            }
            ProcessType::Scale { ratio } => {
                let ratio = C::as_from(ratio as u64);
                c.a_mut().iter_mut().for_each(|v| *v = *v * ratio);
                *c.b_mut() = c.b() * ratio;
            }
            ProcessType::Noop => (),
        }

        let mut acc =
            self.blind_rotation_key
                .blind_rotate(lut, &c, parameters.blind_rotation_basis());

        acc.b_mut()[0] += Q::new(Q::MODULUS_VALUE >> 3u32);

        match parameters.steps() {
            Steps::BrMsKs => {
                let acc = acc.extract_lwe_locally();
                let cipher = lwe_modulus_switch(acc, parameters.lwe_cipher_modulus_value());

                let ksk = match self.key_switching_key {
                    KeySwitchingKeyEnum::LWE(ref ksk) => ksk,
                    _ => panic!("Unable to get the corresponding key switching key!"),
                };

                c = ksk.key_switch_for_lwe(cipher);
            }
            Steps::BrKsMs => {
                let ksk = match self.key_switching_key {
                    KeySwitchingKeyEnum::RLWE(ref ksk) => ksk,
                    _ => panic!("Unable to get the corresponding key switching key!"),
                };

                let key_switched = ksk.key_switch_for_rlwe(acc);

                lwe_modulus_switch_inplace(
                    key_switched,
                    parameters.lwe_cipher_modulus_value(),
                    &mut c,
                );
            }
            Steps::BrMs => {
                let lwe = acc.extract_lwe_locally();

                lwe_modulus_switch_inplace(lwe, parameters.lwe_cipher_modulus_value(), &mut c);
            }
        }

        c
    }
}

/// Evaluator
#[derive(Debug, Clone)]
pub struct Evaluator<C: LWEModulusType, Q: NTTField> {
    ek: EvaluationKey<C, Q>,
}

impl<C: LWEModulusType, Q: NTTField> Evaluator<C, Q> {
    /// Create a new instance.
    #[inline]
    pub fn new(sk: &SecretKeyPack<C, Q>) -> Self {
        Self {
            ek: EvaluationKey::new(sk),
        }
    }

    /// Returns a reference to the parameters of this [`Evaluator<F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<C, Q> {
        self.ek.parameters()
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and lookup table `lut`.
    #[inline]
    pub fn bootstrap(&self, c: LWECiphertext<C>, lut: Polynomial<Q>) -> LWECiphertext<C> {
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
    pub fn not(&self, c: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let mut neg = c.neg_reduce(lwe_modulus);
        neg.b_mut()
            .add_reduce_assign(parameters.lwe_cipher_modulus_value() >> 2u32, lwe_modulus);
        neg
    }

    /// Performs the homomorphic nand operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a and b)`.
    pub fn nand(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let lut = init_nand_lut(parameters.ring_dimension(), parameters.lut_step());

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic and operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a and b`.
    pub fn and(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let lut: Polynomial<Q> =
            init_and_majority_lut(parameters.ring_dimension(), parameters.lut_step());

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic or operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a or b`.
    pub fn or(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let lut = init_or_lut(parameters.ring_dimension(), parameters.lut_step());

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic nor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a or b)`.
    pub fn nor(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let lut = init_nor_lut(parameters.ring_dimension(), parameters.lut_step());

        self.bootstrap(add, lut)
    }

    /// Performs the homomorphic xor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a xor b`.
    pub fn xor(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplace(C::TWO, lwe_modulus);

        let lut = init_xor_lut(parameters.ring_dimension(), parameters.lut_step());

        self.bootstrap(sub, lut)
    }

    /// Performs the homomorphic xnor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a xor b)`.
    pub fn xnor(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplace(C::TWO, lwe_modulus);

        let lut = init_xnor_lut(parameters.ring_dimension(), parameters.lut_step());

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
    ///     If there are two or three `true`(resp. `false`) in `a`, `b` and `c`, it will return `true`(resp. `false`).
    pub fn majority(
        &self,
        c0: &LWECiphertext<C>,
        c1: &LWECiphertext<C>,
        c2: &LWECiphertext<C>,
    ) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);
        add.add_reduce_inplace_component_wise(c2, lwe_modulus);

        let lut = init_and_majority_lut(parameters.ring_dimension(), parameters.lut_step());

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
    ///     If `a` is `true`, it will return `b`. If `a` is `false`, it will return `c`.
    pub fn mux(
        &self,
        c0: &LWECiphertext<C>,
        c1: &LWECiphertext<C>,
        c2: &LWECiphertext<C>,
    ) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let not_c0 = self.not(c0);

        let (mut t0, t1) = rayon::join(|| self.and(c0, c1), || self.and(&not_c0, c2));

        // (a & b) | (!a & c)
        t0.add_reduce_inplace_component_wise(&t1, lwe_modulus);

        let lut = init_or_lut(parameters.ring_dimension(), parameters.lut_step());

        self.bootstrap(t0, lut)
    }
}

/// init lut for bootstrapping which performs homomorphic `nand`.
fn init_nand_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> Polynomial<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3u32);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_nand_and_majority_lut(
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init lut for bootstrapping which performs homomorphic `and` or `majority`.
fn init_and_majority_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> Polynomial<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3u32);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_nand_and_majority_lut(
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init lut for bootstrapping which performs homomorphic `nand`, `and` or `majority`.
fn init_nand_and_majority_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    value_0_1: F, // [−q/8, 3q/8)
    value_2_3: F, // [3q/8, 7q/8)
) -> Polynomial<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let mid = (rlwe_dimension >> 1) + (rlwe_dimension >> 2); // 3N/4

    v[..mid]
        .iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| *a = value_0_1);

    v[mid..]
        .iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| *a = value_2_3);

    v
}

/// init lut for bootstrapping which performs homomorphic `or` or `xor`.
fn init_or_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> Polynomial<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3u32);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_or_nor_lut(
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init lut for bootstrapping which performs homomorphic `nor` or `xnor`.
fn init_nor_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> Polynomial<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3u32);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_or_nor_lut(
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init lut for bootstrapping which performs homomorphic `xor`.
fn init_xor_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> Polynomial<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3u32);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_xor_xnor_lut(
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init lut for bootstrapping which performs homomorphic `xnor`.
fn init_xnor_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> Polynomial<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3u32);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_xor_xnor_lut(
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init lut for bootstrapping which performs homomorphic `or`, `nor`, `xor` or `xnor`.
fn init_or_nor_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    value_1_2: F, // [q/8, 5q/8)
    value_3_0: F, // [−3q/8, q/8)
) -> Polynomial<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let mid = rlwe_dimension >> 2; // N/4

    v[..mid]
        .iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| *a = value_3_0);

    v[mid..]
        .iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| *a = value_1_2);

    v
}

/// init lut for bootstrapping which performs homomorphic `xor` or `xnor`.
fn init_xor_xnor_lut<F>(
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    value_2: F, // [q/4, 3q/4)
    value_0: F, // [−q/4, q/4)
) -> Polynomial<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let mid = rlwe_dimension >> 1; // N/2

    v[..mid]
        .iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| *a = value_0);

    v[mid..]
        .iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| *a = value_2);

    v
}
