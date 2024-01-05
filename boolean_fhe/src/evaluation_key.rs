use algebra::{NTTField, Polynomial, RandomNTTField, Ring};
use lattice::RLWE;

use crate::{
    ciphertext::RLWECiphertext, BootstrappingKey, KeySwitchingKey, LWECiphertext, Parameters,
    SecretKeyPack,
};

/// The evaluator of the homomorphic encryption scheme.
pub struct EvaluationKey<R: Ring, F: NTTField> {
    bootstrapping_key: BootstrappingKey<F>,
    key_switching_key: KeySwitchingKey<F>,
    parameters: Parameters<R, F>,
}

impl<R: Ring, F: NTTField> EvaluationKey<R, F> {
    /// Returns the parameters of this [`EvaluationKey<R, F>`].
    #[inline]
    pub fn parameters(&self) -> &Parameters<R, F> {
        &self.parameters
    }

    /// nand
    pub fn nand(&self, c0: LWECiphertext<R>, c1: &LWECiphertext<R>) -> LWECiphertext<R> {
        let parameters = self.parameters();

        let add = c0.add_component_wise(c1);

        let init_acc: RLWECiphertext<F> = init_nand_acc(
            add.b(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        self.bootstrap(add, init_acc)
    }

    fn bootstrap(&self, c: LWECiphertext<R>, init_acc: RLWECiphertext<F>) -> LWECiphertext<R> {
        let parameters = self.parameters();

        let acc = self.bootstrapping_key.bootstrapping(
            init_acc,
            c.a(),
            parameters.rlwe_dimension(),
            parameters.twice_rlwe_dimension_div_lwe_modulus(),
        );

        let mut extract = acc.extract_lwe();
        *extract.b_mut() += F::Q_DIV_8;

        self.key_switching_key
            .key_switch(extract, parameters.lwe_dimension())
            .modulus_switch_floor(
                self.parameters.lwe_modulus_f64(),
                self.parameters.rlwe_modulus_f64(),
            )
    }
}

impl<R: Ring, F: RandomNTTField> EvaluationKey<R, F> {
    /// .
    pub fn new<Rng>(secret_key_pack: &SecretKeyPack<R, F>, mut rng: Rng) -> Self
    where
        Rng: rand::Rng + rand::CryptoRng,
    {
        let lwe_secret_key = secret_key_pack.lwe_secret_key();

        let parameters = secret_key_pack.parameters();
        let chi = parameters.rlwe_noise_distribution();

        let bootstrapping_key = BootstrappingKey::generate(
            parameters.secret_key_type(),
            lwe_secret_key,
            secret_key_pack.ntt_rlwe_secret_key(),
            parameters.rlwe_dimension(),
            parameters.gadget_basis(),
            parameters.gadget_basis_powers(),
            chi,
            &mut rng,
        );

        let key_switching_key = KeySwitchingKey::generate(
            parameters.lwe_dimension(),
            lwe_secret_key,
            secret_key_pack.rlwe_secret_key(),
            parameters.key_switching_basis(),
            parameters.key_switching_basis_powers(),
            chi,
            rng,
        );

        Self {
            bootstrapping_key,
            key_switching_key,
            parameters: Clone::clone(&secret_key_pack.parameters()),
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
