use algebra::{reduce::AddReduceAssign, NTTField, Polynomial};
use fhe_core::{
    lwe_modulus_switch_inplace, BlindRotationType, KeySwitchingKey, LWECiphertext, LWEModulusType,
    Parameters, RLWEBlindRotationKey, RLWECiphertext, SecretKeyPack, StepsAfterBr,
};
use lattice::RLWE;

/// The evaluator of the homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct EvaluationKey<F: NTTField> {
    /// Blind rotation key
    blind_rotation_key: RLWEBlindRotationKey<F>,
    /// Key Switching Key
    key_switching_key: KeySwitchingKey<F>,
    /// The parameters of the fully homomorphic encryption scheme.
    parameters: Parameters<F>,
}

impl<F: NTTField> EvaluationKey<F> {
    /// Returns the parameters of this [`EvaluationKey<F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<F> {
        &self.parameters
    }

    /// Creates a new [`EvaluationKey`] from the given [`SecretKeyPack`].
    pub fn new(secret_key_pack: &SecretKeyPack<F>) -> Self {
        let mut csrng = secret_key_pack.csrng_mut();
        let parameters = secret_key_pack.parameters();

        assert_eq!(parameters.blind_rotation_type(), BlindRotationType::RLWE);

        let chi = parameters.ring_noise_distribution();
        let blind_rotation_key = RLWEBlindRotationKey::generate(secret_key_pack, chi, &mut *csrng);

        let key_switching_key;

        match parameters.steps_after_blind_rotation() {
            StepsAfterBr::KsMs => {
                let chi = parameters.key_switching_noise_distribution();
                key_switching_key = KeySwitchingKey::generate(secret_key_pack, chi, &mut *csrng);
            }
            StepsAfterBr::Ms => key_switching_key = KeySwitchingKey::default(),
        }

        Self {
            blind_rotation_key,
            key_switching_key,
            parameters: *parameters,
        }
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and initial `ACC`.
    pub fn bootstrap(&self, mut c: LWECiphertext, init_acc: RLWECiphertext<F>) -> LWECiphertext {
        let parameters = self.parameters();

        let mut acc = self.blind_rotation_key.blind_rotate(
            init_acc,
            c.a(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
            parameters.lwe_modulus(),
            parameters.blind_rotation_basis(),
        );

        acc.b_mut()[0] += F::new(F::MODULUS_VALUE >> 3);

        match parameters.steps_after_blind_rotation() {
            StepsAfterBr::KsMs => {
                let key_switched = self.key_switching_key.key_switch_for_rlwe(&acc);

                lwe_modulus_switch_inplace(key_switched, parameters.lwe_modulus().value(), &mut c);
            }
            StepsAfterBr::Ms => {
                let lwe = acc.extract_lwe_reverse_locally();

                lwe_modulus_switch_inplace(lwe, parameters.lwe_modulus().value(), &mut c);
            }
        }

        c
    }
}

/// Evaluator
#[derive(Debug, Clone)]
pub struct Evaluator<F: NTTField> {
    ek: EvaluationKey<F>,
}

impl<F: NTTField> Evaluator<F> {
    /// Create a new instance.
    #[inline]
    pub fn new(sk: &SecretKeyPack<F>) -> Self {
        Self {
            ek: EvaluationKey::new(sk),
        }
    }

    /// Returns a reference to the parameters of this [`Evaluator<F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<F> {
        self.ek.parameters()
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and initial `ACC`.
    #[inline]
    pub fn bootstrap(&self, c: LWECiphertext, init_acc: RLWECiphertext<F>) -> LWECiphertext {
        self.ek.bootstrap(c, init_acc)
    }

    /// Performs the homomorphic not operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c`, with message `true`(resp. `false`).
    /// * Output: ciphertext with message `false`(resp. `true`).
    ///
    /// Link: https://eprint.iacr.org/2020/086
    pub fn not(&self, c: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut neg = c.neg_reduce(lwe_modulus);
        neg.b_mut()
            .add_reduce_assign(lwe_modulus.value() >> 2, lwe_modulus);
        neg
    }

    /// Performs the homomorphic nand operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a and b)`.
    pub fn nand(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_nand_acc(
            add.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic and operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a and b`.
    pub fn and(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_and_majority_acc(
            add.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic or operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a or b`.
    pub fn or(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_or_acc(
            add.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic nor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a or b)`.
    pub fn nor(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_nor_acc(
            add.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic xor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a xor b`.
    pub fn xor(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplac(2, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_xor_acc(
            sub.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(sub, init_acc)
    }

    /// Performs the homomorphic xnor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a xor b)`.
    pub fn xnor(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplac(2, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_xnor_acc(
            sub.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(sub, init_acc)
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
        c0: &LWECiphertext,
        c1: &LWECiphertext,
        c2: &LWECiphertext,
    ) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);
        add.add_reduce_inplace_component_wise(c2, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_and_majority_acc(
            add.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
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
    pub fn mux(&self, c0: &LWECiphertext, c1: &LWECiphertext, c2: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let not_c0 = self.not(c0);

        let (mut t0, t1) = rayon::join(|| self.and(c0, c1), || self.and(&not_c0, c2));

        // (a & b) | (!a & c)
        t0.add_reduce_inplace_component_wise(&t1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_or_acc(
            t0.b(),
            parameters.ring_dimension(),
            parameters.twice_ring_dimension_div_lwe_modulus(),
        );

        self.bootstrap(t0, init_acc)
    }
}

/// init acc for bootstrapping which performs homomorphic `nand`.
fn init_nand_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_nand_and_majority_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `and` or `majority`.
fn init_and_majority_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_nand_and_majority_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `nand`, `and` or `majority`.
fn init_nand_and_majority_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    value_0_1: F, // [−q/8, 3q/8)
    value_2_3: F, // [3q/8, 7q/8)
) -> RLWE<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let b = b as usize * twice_rlwe_dimension_div_lwe_modulus;

    let x = rlwe_dimension >> 2; // N/4
    let y = (rlwe_dimension >> 1) + x; // 3N/4
    let z = rlwe_dimension + y; // 7N/4
    if b < y || b >= z {
        let mid = if b < y { b + x } else { b - z };
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_0_1);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_2_3);
    } else {
        let mid = b - y;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_2_3);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_0_1);
    }

    RLWE::new(Polynomial::zero(rlwe_dimension), v)
}

/// init acc for bootstrapping which performs homomorphic `or` or `xor`.
fn init_or_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_or_nor_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `nor` or `xnor`.
fn init_nor_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_or_nor_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `xor`.
fn init_xor_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_xor_xnor_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `xnor`.
fn init_xnor_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_xor_xnor_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `or`, `nor`, `xor` or `xnor`.
fn init_or_nor_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    value_1_2: F, // [q/8, 5q/8)
    value_3_0: F, // [−3q/8, q/8)
) -> RLWE<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let b = b as usize * twice_rlwe_dimension_div_lwe_modulus;

    let x = rlwe_dimension >> 2; // N/4
    let y = (rlwe_dimension >> 1) + x; // 3N/4
    let z = rlwe_dimension + x; // 5N/4
    if b < x || b >= z {
        let mid = if b < x { b + y } else { b - z };
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_3_0);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_1_2);
    } else {
        let mid = b - x;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_1_2);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_3_0);
    }

    RLWE::new(Polynomial::zero(rlwe_dimension), v)
}

/// init acc for bootstrapping which performs homomorphic `xor` or `xnor`.
fn init_xor_xnor_acc<F>(
    b: LWEModulusType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    value_2: F, // [q/4, 3q/4)
    value_0: F, // [−q/4, q/4)
) -> RLWE<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let b = b as usize * twice_rlwe_dimension_div_lwe_modulus;

    let x = rlwe_dimension >> 1; // N/2
    let y = rlwe_dimension + x; // 3N/2
    if b < x || b >= y {
        let mid = if b < x { b + x } else { b - y };
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_0);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_2);
    } else {
        let mid = b - x;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_2);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_0);
    }

    RLWE::new(Polynomial::zero(rlwe_dimension), v)
}
