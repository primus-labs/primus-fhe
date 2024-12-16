use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField};
use lattice::{DecompositionSpace, NTTRLWESpace, PolynomialSpace, RLWESpace};
use rand::{CryptoRng, Rng};

use crate::{AutoKey, NTTRLWESecretKey, RLWECiphertext, RLWESecretKey};

///
pub struct TraceKey<F: NTTField> {
    auto_keys: Vec<AutoKey<F>>,
}

impl<F: NTTField> TraceKey<F> {
    ///
    pub fn new_with_secret_key<R>(
        sk: &RLWESecretKey<F>,
        ntt_sk: &NTTRLWESecretKey<F>,
        basis: Basis<F>,
        error_sampler: FieldDiscreteGaussianSampler,
        rng: &mut R,
    ) -> TraceKey<F>
    where
        R: Rng + CryptoRng,
    {
        let log_n = sk.coeff_count().trailing_zeros();
        let auto_keys: Vec<AutoKey<F>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| {
                AutoKey::new_with_secret_key(sk, ntt_sk, degree, basis, error_sampler, rng)
            })
            .collect();

        Self { auto_keys }
    }

    ///
    pub fn trace(&self, ciphertext: &RLWECiphertext<F>) -> RLWECiphertext<F> {
        let dimension = ciphertext.dimension();
        let mut destination = ciphertext.clone();

        let rlwe_space = &mut RLWESpace::new(dimension);
        let decompose_space = &mut DecompositionSpace::new(dimension);
        let polynomial_space = &mut PolynomialSpace::new(dimension);
        let ntt_rlwe_space = &mut NTTRLWESpace::new(dimension);

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_inplace(
                &destination,
                decompose_space,
                polynomial_space,
                ntt_rlwe_space,
                rlwe_space,
            );
            destination.add_assign_element_wise(rlwe_space);
        }

        destination
    }

    ///
    pub fn trace_inplace(
        &self,
        ciphertext: &RLWECiphertext<F>,
        // Pre allocate space for decomposition
        rlwe_space: &mut RLWESpace<F>,
        decompose_space: &mut DecompositionSpace<F>,
        polynomial_space: &mut PolynomialSpace<F>,
        ntt_rlwe_space: &mut NTTRLWESpace<F>,
        // Output destination
        destination: &mut RLWECiphertext<F>,
    ) {
        destination.a_mut().copy_from(ciphertext.a());
        destination.b_mut().copy_from(ciphertext.b());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_inplace(
                destination,
                decompose_space,
                polynomial_space,
                ntt_rlwe_space,
                rlwe_space,
            );
            destination.add_assign_element_wise(rlwe_space);
        }
    }
}

#[cfg(test)]
mod tests {
    use algebra::{FheField, Field, ModulusConfig, Polynomial};
    use num_traits::Inv;
    use rand::{distributions::Uniform, prelude::Distribution};

    use crate::DefaultFieldU32;

    use super::*;

    type FF = DefaultFieldU32;
    type Inner = u32; // inner type
    type PolyFF = Polynomial<FF>;

    const FP: Inner = FF::MODULUS.value(); // ciphertext space
    const FT: Inner = 8; // message space

    const N: usize = 1024;

    #[inline]
    fn encode(m: Inner) -> FF {
        FF::new((m as f64 * FP as f64 / FT as f64).round() as Inner)
    }

    #[inline]
    fn decode(c: FF) -> Inner {
        (c.value() as f64 * FT as f64 / FP as f64).round() as Inner % FT
    }

    #[test]
    fn test_trace() {
        let mut csrng = rand::thread_rng();
        let error_sampler = FieldDiscreteGaussianSampler::new(0.0, 3.2).unwrap();
        let dis = Uniform::new(0, FT);

        let sk = <Polynomial<FF>>::random_with_ternary(N, &mut csrng);
        let ntt_sk = sk.clone().into_ntt_polynomial();

        let trace_key =
            TraceKey::new_with_secret_key(&sk, &ntt_sk, Basis::new(1), error_sampler, &mut csrng);

        let values: Vec<Inner> = dis.sample_iter(&mut csrng).take(N).collect();
        let encoded_values = PolyFF::new(values.iter().copied().map(encode).collect());

        let mut cipher =
            <RLWECiphertext<FF>>::generate_random_zero_sample(&ntt_sk, error_sampler, &mut csrng);
        *cipher.b_mut() += &encoded_values;

        let n_inv = FF::lazy_new(N as Inner).inv();
        cipher.a_mut().mul_scalar_assign(n_inv);
        cipher.b_mut().mul_scalar_assign(n_inv);

        let result = trace_key.trace(&cipher);

        let decrypted_values = (result.b() - result.a() * &ntt_sk)
            .into_iter()
            .map(decode)
            .collect::<Vec<u32>>();
        let flag =
            decrypted_values[0] == values[0] && decrypted_values[1..].iter().all(|&v| v == 0);

        assert!(flag);
    }
}
