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
