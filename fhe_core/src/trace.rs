use algebra::{Basis, FieldDiscreteGaussianSampler, NTTField};
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
        let auto_keys: Vec<AutoKey<F>> = (0..log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| {
                AutoKey::new_with_secret_key(sk, ntt_sk, degree, basis, error_sampler, rng)
            })
            .collect();

        Self { auto_keys }
    }

    ///
    pub fn trace_inplace(&self, ciphertext: &RLWECiphertext<F>) -> RLWECiphertext<F> {
        // let log_n = ciphertext.b().coeff_count().trailing_zeros();
        // for k in (0..log_n).rev().map(|x| (1usize << x) + 1) {

        // }

        let mut result = ciphertext.clone();

        for auto_key in self.auto_keys.iter() {
            let auto_result = auto_key.automorphism(&result);
            result.add_assign_element_wise(&auto_result);
        }

        result
    }
}
