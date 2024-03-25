use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial, RandomNTTField};
use lattice::{LWE, RLWE};
use rand_distr::Distribution;

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

impl<F: RandomNTTField> EvaluationKey<F>
where
    FieldDiscreteGaussianSampler: Distribution<F>,
{
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
            .for_each(|a| *a = F::Q_DIV_8);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = F::NEG_Q_DIV_8);
    } else {
        let mid = b - y;
        v[0..=mid]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus)
            .for_each(|a| *a = F::NEG_Q_DIV_8);

        let mut iter = v[mid..]
            .iter_mut()
            .step_by(twice_rlwe_dimension_div_lwe_modulus);
        iter.next();
        iter.for_each(|a| *a = F::Q_DIV_8);
    }

    RLWE::new(Polynomial::zero(rlwe_dimension), v)
}

#[test]
fn test_init_nand_acc() {
    use std::ops::Neg;

    use algebra::modulus::PowOf2Modulus;
    use algebra::reduce::{NegReduce, SubReduce};
    use algebra::Field;

    use crate::DefaultField100;

    const N: usize = 64;
    let q = 16u16;
    let modulus = <PowOf2Modulus<u16>>::new(q);
    let ratio = N * 2 / (q as usize);
    let l = (q >> 3) * 3;
    let r = (q >> 3) * 7;
    for b in 0..q {
        let acc = init_nand_acc::<DefaultField100>(b, N, ratio);
        for a in 0..q {
            let ra = a.neg_reduce(modulus) as usize * ratio;
            let m = if ra == 0 {
                acc.b()[0]
            } else if ra < N {
                acc.b()[N - ra].neg()
            } else if ra == N {
                acc.b()[0].neg()
            } else {
                acc.b()[2 * N - ra]
            };

            if (l..r).contains(&(b.sub_reduce(a, modulus))) {
                assert_eq!(m, DefaultField100::NEG_Q_DIV_8, "b:{b} a:{a}");
            } else {
                assert_eq!(m, DefaultField100::Q_DIV_8, "b:{b} a:{a}");
            }
        }
    }
}
