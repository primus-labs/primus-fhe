use algebra::{AsInto, NTTField, Polynomial};
use fhe_core::{
    lwe_modulus_switch_between_modulus_inplace, lwe_modulus_switch_inplace, BlindRotationType,
    KeySwitchingKeyEnum, KeySwitchingRLWEKey, LWECiphertext, LWEModulusType, NTRUBlindRotationKey,
    NTRUCiphertext, Parameters, SecretKeyPack, Steps,
};
use lattice::NTRU;

/// The evaluator of the homomorphic encryption scheme.
#[derive(Debug, Clone)]
pub struct EvaluationKey<C: LWEModulusType, Q: NTTField> {
    /// Blind rotation key
    blind_rotation_key: NTRUBlindRotationKey<Q>,
    /// Key Switching Key
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
        assert_eq!(parameters.blind_rotation_type(), BlindRotationType::NTRU);

        let blind_rotation_key = NTRUBlindRotationKey::generate(secret_key_pack);

        let key_switching_key = match parameters.steps() {
            Steps::BrKsMs => {
                KeySwitchingKeyEnum::RLWE(KeySwitchingRLWEKey::generate(secret_key_pack))
            }
            Steps::BrMsKs => unimplemented!(),
            Steps::BrMs => panic!(),
        };

        Self {
            blind_rotation_key,
            key_switching_key,
            parameters: *parameters,
        }
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and initial `ACC`.
    pub fn bootstrap(
        &self,
        mut c: LWECiphertext<C>,
        init_acc: NTRUCiphertext<Q>,
    ) -> LWECiphertext<C> {
        let parameters = self.parameters();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let factor = ms.twice_ring_dimension_div_lwe_cipher_modulus();

        let mut acc = self.blind_rotation_key.blind_rotate(
            init_acc,
            c.a(),
            parameters.ring_dimension(),
            factor,
            ms.lwe_cipher_modulus_for_blind_rotation(),
            parameters.blind_rotation_basis(),
        );

        let half_delta = Q::new(Q::MODULUS_VALUE >> 3);

        acc.data_mut()
            .iter_mut()
            .step_by(factor)
            .for_each(|v| *v += half_delta);

        match parameters.steps() {
            Steps::BrMsKs => unimplemented!(),
            Steps::BrKsMs => {
                let ksk = match self.key_switching_key {
                    KeySwitchingKeyEnum::RLWE(ref ksk) => ksk,
                    _ => panic!(),
                };

                let key_switched = ksk.key_switch_for_ntru(acc);

                lwe_modulus_switch_inplace(
                    key_switched,
                    parameters.lwe_cipher_modulus_value(),
                    parameters.modulus_switch_round_method(),
                    &mut c,
                );
                c
            }
            Steps::BrMs => panic!(),
        }
    }
}

/// Evaluator
#[derive(Debug, Clone)]
pub struct Evaluator<C: LWEModulusType, Q: NTTField> {
    ek: EvaluationKey<C, Q>,
}

impl<C: LWEModulusType, Q: NTTField> Evaluator<C, Q> {
    /// Create a new instance.
    pub fn new(sk: &SecretKeyPack<C, Q>) -> Self {
        Self {
            ek: EvaluationKey::new(sk),
        }
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
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();

        let mut neg = c.neg_reduce(lwe_modulus);
        neg.b_mut()
            .add_reduce_assign(lwe_modulus.value() >> 2u32, lwe_modulus);
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
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut add,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_nand_acc(
            add.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic and operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a and b`.
    pub fn and(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut add,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_and_majority_acc(
            add.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic or operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a or b`.
    pub fn or(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut add,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_or_acc(
            add.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic nor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a or b)`.
    pub fn nor(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut add,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_nor_acc(
            add.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic xor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `a xor b`.
    pub fn xor(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplace(C::TWO, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut sub,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_xor_acc(
            sub.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(sub, init_acc)
    }

    /// Performs the homomorphic xnor operation.
    ///
    /// # Arguments
    ///
    /// * Input: ciphertext `c0`, with message `a`.
    /// * Input: ciphertext `c1`, with message `b`.
    /// * Output: ciphertext with message `not(a xor b)`.
    pub fn xnor(&self, c0: &LWECiphertext<C>, c1: &LWECiphertext<C>) -> LWECiphertext<C> {
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplace(C::TWO, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut sub,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_xnor_acc(
            sub.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(sub, init_acc)
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
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let mut add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);
        add.add_reduce_inplace_component_wise(c2, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut add,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_and_majority_acc(
            add.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(add, init_acc)
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
        let parameters = self.ek.parameters();
        let lwe_modulus = parameters.lwe_cipher_modulus();
        let ms = parameters.modulus_switch_before_blind_rotation();

        let not_c0 = self.not(c0);

        let (mut t0, t1) = rayon::join(|| self.and(c0, c1), || self.and(&not_c0, c2));

        // (a & b) | (!a & c)
        t0.add_reduce_inplace_component_wise(&t1, lwe_modulus);

        if ms.need_modulus_switch() {
            lwe_modulus_switch_between_modulus_inplace(
                &mut t0,
                parameters.lwe_cipher_modulus_value(),
                ms.new_lwe_cipher_modulus_value(),
                parameters.modulus_switch_round_method(),
            );
        }

        let init_acc: NTRUCiphertext<Q> = init_or_acc(
            t0.b(),
            parameters.ring_dimension(),
            ms.twice_ring_dimension_div_lwe_cipher_modulus(),
        );

        self.ek.bootstrap(t0, init_acc)
    }
}

/// init acc for bootstrapping which performs homomorphic `nand`.
fn init_nand_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_nand_and_majority_acc(
        b,
        ntru_dimension,
        twice_ntru_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `and` or `majority`.
fn init_and_majority_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_nand_and_majority_acc(
        b,
        ntru_dimension,
        twice_ntru_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `nand`, `and` or `majority`.
fn init_nand_and_majority_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
    value_0_1: F, // [−q/8, 3q/8)
    value_2_3: F, // [3q/8, 7q/8)
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let mut v = Polynomial::zero(ntru_dimension);

    let b = AsInto::<usize>::as_into(b) * twice_ntru_dimension_div_lwe_modulus;

    let x = ntru_dimension >> 2; // N/4
    let y = (ntru_dimension >> 1) + x; // 3N/4
    let z = ntru_dimension + y; // 7N/4
    if b < y || b >= z {
        let mid = if b < y { b + x } else { b - z };
        v[0..=mid]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_0_1);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_2_3);
    } else {
        let mid = b - y;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_2_3);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_0_1);
    }

    NTRU::new(v)
}

/// init acc for bootstrapping which performs homomorphic `or` or `xor`.
fn init_or_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_or_nor_acc(
        b,
        ntru_dimension,
        twice_ntru_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `nor` or `xnor`.
fn init_nor_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_or_nor_acc(
        b,
        ntru_dimension,
        twice_ntru_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `xor`.
fn init_xor_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_xor_xnor_acc(
        b,
        ntru_dimension,
        twice_ntru_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `xnor`.
fn init_xnor_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.value());

    init_xor_xnor_acc(
        b,
        ntru_dimension,
        twice_ntru_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

/// init acc for bootstrapping which performs homomorphic `or`, `nor`, `xor` or `xnor`.
fn init_or_nor_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
    value_1_2: F, // [q/8, 5q/8)
    value_3_0: F, // [−3q/8, q/8)
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let mut v = Polynomial::zero(ntru_dimension);

    let b = AsInto::<usize>::as_into(b) * twice_ntru_dimension_div_lwe_modulus;

    let x = ntru_dimension >> 2; // N/4
    let y = (ntru_dimension >> 1) + x; // 3N/4
    let z = ntru_dimension + x; // 5N/4
    if b < x || b >= z {
        let mid = if b < x { b + y } else { b - z };
        v[0..=mid]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_3_0);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_1_2);
    } else {
        let mid = b - x;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_1_2);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_3_0);
    }

    NTRU::new(v)
}

/// init acc for bootstrapping which performs homomorphic `xor` or `xnor`.
fn init_xor_xnor_acc<C, F>(
    b: C,
    ntru_dimension: usize,
    twice_ntru_dimension_div_lwe_modulus: usize,
    value_2: F, // [q/4, 3q/4)
    value_0: F, // [−q/4, q/4)
) -> NTRU<F>
where
    F: NTTField,
    C: LWEModulusType,
{
    let mut v = Polynomial::zero(ntru_dimension);

    let b = AsInto::<usize>::as_into(b) * twice_ntru_dimension_div_lwe_modulus;

    let x = ntru_dimension >> 1; // N/2
    let y = ntru_dimension + x; // 3N/2
    if b < x || b >= y {
        let mid = if b < x { b + x } else { b - y };
        v[0..=mid]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_0);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_2);
    } else {
        let mid = b - x;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus)
            .for_each(|a| *a = value_2);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_ntru_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = value_0);
    }

    NTRU::new(v)
}
