use algebra::{reduce::AddReduceAssign, AsInto, NTTField, Polynomial};
use lattice::{LWE, RLWE};

use crate::{
    BootstrappingKey, KeySwitchingKey, LWECiphertext, LWEType, Parameters, RLWECiphertext,
    SecretKeyPack,
};

/// The evaluator of the homomorphic encryption scheme.
pub struct EvaluationKey<F: NTTField> {
    /// Bootstrapping key
    bootstrapping_key: BootstrappingKey<F>,
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

    /// Performs the homomorphic nand operation.
    pub fn not(&self, c: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut neg = c.neg_reduce(lwe_modulus);
        neg.b_mut()
            .add_reduce_assign(lwe_modulus.value() >> 2, lwe_modulus);
        neg
    }

    /// Performs the homomorphic nand operation.
    pub fn nand(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_nand_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic and operation.
    pub fn and(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_and_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic or operation.
    pub fn or(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_or_xor_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic nor operation.
    pub fn nor(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_nor_xnor_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Performs the homomorphic xor operation.
    pub fn xor(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplac(2, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_or_xor_acc(
            sub.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(sub, init_acc)
    }

    /// Performs the homomorphic xnor operation.
    pub fn xnor(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let mut sub = c0.sub_reduce_component_wise_ref(c1, lwe_modulus);
        sub.scalar_mul_reduce_inplac(2, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_nor_xnor_acc(
            sub.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(sub, init_acc)
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and initial `ACC`.
    pub fn bootstrap(&self, c: LWECiphertext, init_acc: RLWECiphertext<F>) -> LWECiphertext {
        let parameters = self.parameters();

        let acc = self.bootstrapping_key.bootstrapping(
            init_acc,
            c.a(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
            parameters.lwe_modulus(),
            parameters.bootstrapping_basis(),
        );

        let mut extract = acc.extract_lwe();
        *extract.b_mut() += F::new(F::MODULUS_VALUE >> 3);

        let key_switched = self.key_switching_key.key_switch(extract);
        self.modulus_switch(key_switched)
    }

    /// Performs modulus switch.
    pub fn modulus_switch(&self, c: LWE<F>) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus_f64 = parameters.lwe_modulus_f64();
        let rlwe_modulus_f64 = parameters.rlwe_modulus_f64();

        let switch =
            |v: F| (v.get().as_into() * lwe_modulus_f64 / rlwe_modulus_f64).floor() as LWEType;

        let a: Vec<LWEType> = c.a().iter().copied().map(switch).collect();
        let b = switch(c.b());

        LWECiphertext::new(a, b)
    }
}

impl<F: NTTField> EvaluationKey<F> {
    /// Creates a new [`EvaluationKey`] from the given [`SecretKeyPack`].
    pub fn new(secret_key_pack: &SecretKeyPack<F>) -> Self {
        let mut csrng = secret_key_pack.csrng_mut();
        let parameters = secret_key_pack.parameters();

        let chi = parameters.rlwe_noise_distribution();
        let bootstrapping_key = BootstrappingKey::generate(secret_key_pack, chi, &mut *csrng);

        let chi = parameters.key_switching_noise_distribution();
        let key_switching_key = KeySwitchingKey::generate(secret_key_pack, chi, &mut *csrng);

        Self {
            bootstrapping_key,
            key_switching_key,
            parameters: parameters.clone(),
        }
    }
}

fn init_nand_acc<F>(
    b: LWEType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_nand_and_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

fn init_and_acc<F>(
    b: LWEType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_nand_and_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

fn init_nand_and_acc<F>(
    b: LWEType,
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

fn init_or_xor_acc<F>(
    b: LWEType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_or_nor_xor_xnor_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        q_div_8,
        neg_q_div_8,
    )
}

fn init_nor_xnor_acc<F>(
    b: LWEType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    F: NTTField,
{
    let q = F::MODULUS_VALUE;
    let q_div_8 = F::new(q >> 3);
    let neg_q_div_8 = F::new(q - q_div_8.get());

    init_or_nor_xor_xnor_acc(
        b,
        rlwe_dimension,
        twice_rlwe_dimension_div_lwe_modulus,
        neg_q_div_8,
        q_div_8,
    )
}

fn init_or_nor_xor_xnor_acc<F>(
    b: LWEType,
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
