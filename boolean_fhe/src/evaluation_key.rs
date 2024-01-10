use algebra::{NTTField, Polynomial, RandomNTTField, Ring};
use lattice::RLWE;

use crate::{
    BootstrappingKey, KeySwitchingKey, LWECiphertext, Parameters, RLWECiphertext, SecretKeyPack,
};

/// The evaluator of the homomorphic encryption scheme.
pub struct EvaluationKey<R: Ring, F: NTTField> {
    /// Bootstrapping key
    bootstrapping_key: BootstrappingKey<F>,
    /// Key Switching Key
    key_switching_key: KeySwitchingKey<F>,
    /// The parameters of the fully homomorphic encryption scheme.
    parameters: Parameters<R, F>,
}

impl<R: Ring, F: NTTField> EvaluationKey<R, F> {
    /// Returns the parameters of this [`EvaluationKey<R, F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<R, F> {
        &self.parameters
    }

    /// Performs the homomorphic nand operation.
    pub fn nand(&self, c0: &LWECiphertext<R>, c1: &LWECiphertext<R>) -> LWECiphertext<R> {
        let parameters = self.parameters();

        let add = c0.add_component_wise_ref(c1);

        let init_acc: RLWECiphertext<F> = init_nand_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and initial `ACC`.
    pub fn bootstrap(&self, c: LWECiphertext<R>, init_acc: RLWECiphertext<F>) -> LWECiphertext<R> {
        let parameters = self.parameters();

        let acc = self.bootstrapping_key.bootstrapping(
            init_acc,
            c.a(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
            parameters.gadget_basis(),
        );

        let mut extract = acc.extract_lwe();
        *extract.b_mut() += F::Q_DIV_8;

        self.key_switching_key
            .key_switch(extract)
            .modulus_switch_floor()
    }
}

impl<R: Ring, F: RandomNTTField> EvaluationKey<R, F> {
    /// Creates a new [`EvaluationKey`] from the given [`SecretKeyPack`].
    pub fn new(secret_key_pack: &SecretKeyPack<R, F>) -> Self {
        let mut csrng = secret_key_pack.csrng_mut();

        let parameters = secret_key_pack.parameters();
        let chi = parameters.rlwe_noise_distribution();

        let bootstrapping_key = BootstrappingKey::generate(secret_key_pack, chi, &mut *csrng);

        let key_switching_key = KeySwitchingKey::generate(secret_key_pack, chi, &mut *csrng);

        Self {
            bootstrapping_key,
            key_switching_key,
            parameters: parameters.clone(),
        }
    }
}

fn init_nand_acc<R, F>(
    mut b: R,
    rlwe_dimension: usize,
    twice_rlwe_dimension_div_lwe_modulus: usize,
) -> RLWE<F>
where
    R: Ring,
    F: NTTField,
{
    let mut v = Polynomial::zero_with_coeff_count(rlwe_dimension);

    let l = R::Q3_DIV_8.inner();
    let r = R::Q7_DIV_8.inner();

    v.iter_mut()
        .step_by(twice_rlwe_dimension_div_lwe_modulus)
        .for_each(|a| {
            if (l..r).contains(&b.inner()) {
                *a = F::NRG_Q_DIV_8;
            } else {
                *a = F::Q_DIV_8;
            }
            b -= R::ONE;
        });
    RLWE::new(Polynomial::zero_with_coeff_count(rlwe_dimension), v)
}
