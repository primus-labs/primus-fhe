use algebra::{
    modulus::PowOf2Modulus, reduce::SubReduceAssign, NTTField, Polynomial, RandomNTTField,
};
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
    pub fn nand(&self, c0: &LWECiphertext, c1: &LWECiphertext) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus = parameters.lwe_modulus();

        let add = c0.add_reduce_component_wise_ref(c1, lwe_modulus);

        let init_acc: RLWECiphertext<F> = init_nand_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
            lwe_modulus,
        );

        self.bootstrap(add, init_acc)
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
            parameters.gadget_basis(),
        );

        let mut extract = acc.extract_lwe();
        *extract.b_mut() += F::Q_DIV_8;

        let key_switched = self.key_switching_key.key_switch(extract);
        self.modulus_switch(key_switched)
    }

    /// Performs modulus switch.
    pub fn modulus_switch(&self, c: LWE<F>) -> LWECiphertext {
        let parameters = self.parameters();
        let lwe_modulus_f64 = parameters.lwe_modulus_f64();
        let rlwe_modulus_f64 = parameters.rlwe_modulus_f64();

        let switch = |v: F| (v.to_f64() * lwe_modulus_f64 / rlwe_modulus_f64).floor() as LWEType;

        let a: Vec<LWEType> = c.a().iter().copied().map(switch).collect();
        let b = switch(c.b());

        LWECiphertext::new(a, b)
    }
}

impl<F: RandomNTTField> EvaluationKey<F> {
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
    mut b: LWEType,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
    lwe_modulus: PowOf2Modulus<LWEType>,
) -> RLWE<F>
where
    F: NTTField,
{
    let mut v = Polynomial::zero(rlwe_dimension);

    let lwe_modulus_value = lwe_modulus.value();

    let l = (lwe_modulus_value >> 3) * 3;
    let r = (lwe_modulus_value >> 3) * 7;

    v.iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| {
            if (l..r).contains(&b) {
                *a = F::NRG_Q_DIV_8;
            } else {
                *a = F::Q_DIV_8;
            }
            b.sub_reduce_assign(1, lwe_modulus);
        });
    RLWE::new(Polynomial::zero(rlwe_dimension), v)
}
