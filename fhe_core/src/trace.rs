use std::sync::Arc;

use algebra::{
    decompose::NonPowOf2ApproxSignedBasis, modulus::ShoupFactor, random::DiscreteGaussian,
    utils::Size, AsInto, Field, NttField,
};
use lattice::utils::RlweSpace;
use rand::{CryptoRng, Rng};

use crate::{utils::Pool, AutoKey, AutoSpace, NttRlweSecretKey, RlweCiphertext, RlweSecretKey};

/// Trace key
pub struct TraceKey<F: NttField> {
    auto_keys: Vec<AutoKey<F>>,
    pool: Pool<(RlweSpace<F>, AutoSpace<F>)>,
}

impl<F: NttField> Clone for TraceKey<F> {
    fn clone(&self) -> Self {
        Self {
            auto_keys: self.auto_keys.clone(),
            pool: self.pool.clone(),
        }
    }
}

impl<F: NttField> TraceKey<F> {
    /// Creates a new [`TraceKey<F>`].
    pub fn new<R>(
        secret_key: &RlweSecretKey<F>,
        ntt_secret_key: &NttRlweSecretKey<F>,
        basis: &NonPowOf2ApproxSignedBasis<<F as Field>::ValueT>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: Arc<<F as NttField>::Table>,
        rng: &mut R,
    ) -> TraceKey<F>
    where
        R: Rng + CryptoRng,
    {
        let log_n = secret_key.coeff_count().trailing_zeros();
        let auto_keys: Vec<AutoKey<F>> = (1..=log_n)
            .rev()
            .map(|x| (1usize << x) + 1)
            .map(|degree| {
                AutoKey::new(
                    secret_key,
                    ntt_secret_key,
                    degree,
                    basis,
                    gaussian,
                    Arc::clone(&ntt_table),
                    rng,
                )
            })
            .collect();

        Self {
            auto_keys,
            pool: Pool::new(),
        }
    }

    /// Trace operation
    pub fn trace(&self, ciphertext: &RlweCiphertext<F>) -> RlweCiphertext<F> {
        let dimension = ciphertext.dimension();

        let mut destination = ciphertext.clone();

        let (mut rlwe_space, mut auto_space) = match self.pool.get() {
            Some(space) => space,
            None => (RlweSpace::new(dimension), AutoSpace::new(dimension)),
        };

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_inplace(&destination, &mut auto_space, &mut rlwe_space);
            destination.add_assign_element_wise(&rlwe_space);
        }

        self.pool.store((rlwe_space, auto_space));

        destination
    }

    /// Trace operation in place
    pub fn trace_inplace(
        &self,
        ciphertext: &RlweCiphertext<F>,
        destination: &mut RlweCiphertext<F>,
    ) {
        let dimension = ciphertext.dimension();

        let (mut rlwe_space, mut auto_space) = match self.pool.get() {
            Some(space) => space,
            None => (RlweSpace::new(dimension), AutoSpace::new(dimension)),
        };

        destination.a_mut().copy_from(ciphertext.a());
        destination.b_mut().copy_from(ciphertext.b());

        for auto_key in self.auto_keys.iter() {
            auto_key.automorphism_inplace(destination, &mut auto_space, &mut rlwe_space);
            destination.add_assign_element_wise(&rlwe_space);
        }

        self.pool.store((rlwe_space, auto_space));
    }

    /// Coefficient Expansion Algorithm.
    ///
    /// (Alg. 1)[https://eprint.iacr.org/2024/266.pdf]
    pub fn expand_coefficients(&self, ciphertext: &RlweCiphertext<F>) -> Vec<RlweCiphertext<F>> {
        let dimension = ciphertext.dimension();
        let twice_dimension = dimension << 1;

        let inv_n = F::inv(dimension.as_into());
        let n_inv = ShoupFactor::new(inv_n, F::MODULUS_VALUE);

        let (mut a_1, mut auto_space) = match self.pool.get() {
            Some(space) => space,
            None => (RlweSpace::new(dimension), AutoSpace::new(dimension)),
        };

        let mut ct = ciphertext.clone();

        ct.a_mut().mul_shoup_scalar_assign(n_inv);
        ct.b_mut().mul_shoup_scalar_assign(n_inv);

        let mut elems = vec![ct];

        for (i, auto_key) in self.auto_keys.iter().enumerate() {
            let two_pow_i = 1 << i;
            let mut chunk0 = Vec::with_capacity(two_pow_i << 1);
            let mut chunk1 = Vec::with_capacity(two_pow_i);

            for a_0 in elems.into_iter() {
                auto_key.automorphism_inplace(&a_0, &mut auto_space, &mut a_1);

                chunk0.push(a_0.clone().add_element_wise(&*a_1));

                let t = a_0
                    .sub_element_wise(&*a_1)
                    .mul_monic_monomial(twice_dimension - two_pow_i);
                chunk1.push(t);
            }

            chunk0.append(&mut chunk1);
            elems = chunk0;
        }

        self.pool.store((a_1, auto_space));

        elems
    }
}

impl<F: NttField> Size for TraceKey<F> {
    #[inline]
    fn size(&self) -> usize {
        if self.auto_keys.is_empty() {
            return 0;
        }
        self.auto_keys.len() * self.auto_keys[0].size()
    }
}

#[cfg(test)]
mod tests {
    use algebra::{ntt::NumberTheoryTransform, polynomial::FieldPolynomial, Field, U32FieldEval};
    use rand::{distributions::Uniform, prelude::Distribution};

    use crate::RingSecretKeyType;

    use super::*;

    type FieldT = U32FieldEval<132120577>;
    type ValT = <FieldT as Field>::ValueT; // inner type
    type PolyT = FieldPolynomial<FieldT>;

    const CIPHER_MODULUS: ValT = FieldT::MODULUS_VALUE; // ciphertext space
    const PLAIN_MODULUS: ValT = 8; // message space

    const LOG_N: u32 = 10;
    const N: usize = 1 << LOG_N;

    #[inline]
    fn encode(m: ValT) -> ValT {
        (m as f64 * CIPHER_MODULUS as f64 / PLAIN_MODULUS as f64).round() as ValT
    }

    #[inline]
    fn decode(c: ValT) -> ValT {
        (c as f64 * PLAIN_MODULUS as f64 / CIPHER_MODULUS as f64).round() as ValT % PLAIN_MODULUS
    }

    #[test]
    fn test_trace() {
        let ntt_table = Arc::new(FieldT::generate_ntt_table(LOG_N).unwrap());

        let mut csrng = rand::thread_rng();

        let gaussian = DiscreteGaussian::new(0.0, 3.2, FieldT::MINUS_ONE).unwrap();
        let distr = Uniform::new(0, PLAIN_MODULUS);

        let sk = RlweSecretKey::new(
            PolyT::random_ternary(N, &mut csrng),
            RingSecretKeyType::Ternary,
        );
        let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);

        let basis = NonPowOf2ApproxSignedBasis::new(FieldT::MODULUS_VALUE, 4, None);

        let trace_key = TraceKey::new(
            &sk,
            &ntt_sk,
            &basis,
            gaussian,
            Arc::clone(&ntt_table),
            &mut csrng,
        );

        let values: Vec<ValT> = distr.sample_iter(&mut csrng).take(N).collect();
        let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

        let mut cipher = <RlweCiphertext<FieldT>>::generate_random_zero_sample(
            &ntt_sk, gaussian, &ntt_table, &mut csrng,
        );
        *cipher.b_mut() += &encoded_values;

        let n_inv = FieldT::inv(N as ValT);
        cipher.a_mut().mul_scalar_assign(n_inv);
        cipher.b_mut().mul_scalar_assign(n_inv);

        let result = trace_key.trace(&cipher);

        let a_mul_s =
            ntt_table.inverse_transform_inplace(ntt_table.transform(result.a()) * &*ntt_sk);

        let decrypted_values = (result.b() - a_mul_s)
            .into_iter()
            .map(decode)
            .collect::<Vec<u32>>();
        let flag =
            decrypted_values[0] == values[0] && decrypted_values[1..].iter().all(|&v| v == 0);

        assert!(flag);
    }

    // cargo test -r -p fhe_core --lib -- trace::tests::test_expand_coeffs
    #[test]
    fn test_expand_coeffs() {
        let ntt_table = Arc::new(FieldT::generate_ntt_table(LOG_N).unwrap());

        let mut csrng = rand::thread_rng();

        let gaussian = DiscreteGaussian::new(0.0, 3.2, FieldT::MINUS_ONE).unwrap();
        let distr = Uniform::new(0, 2);

        let sk = RlweSecretKey::new(
            PolyT::random_ternary(N, &mut csrng),
            RingSecretKeyType::Ternary,
        );
        let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);

        let basis = NonPowOf2ApproxSignedBasis::new(FieldT::MODULUS_VALUE, 4, None);

        let trace_key = TraceKey::new(
            &sk,
            &ntt_sk,
            &basis,
            gaussian,
            Arc::clone(&ntt_table),
            &mut csrng,
        );

        let values: Vec<ValT> = distr.sample_iter(&mut csrng).take(N).collect();
        let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

        let mut cipher = <RlweCiphertext<FieldT>>::generate_random_zero_sample(
            &ntt_sk, gaussian, &ntt_table, &mut csrng,
        );
        *cipher.b_mut() += &encoded_values;

        let result = trace_key.expand_coefficients(&cipher);

        let flag = result.into_iter().zip(values).all(|(cipher, value)| {
            let a_mul_s =
                ntt_table.inverse_transform_inplace(ntt_table.transform(cipher.a()) * &*ntt_sk);
            let decrypted_values = (cipher.b() - a_mul_s)
                .into_iter()
                .map(decode)
                .collect::<Vec<ValT>>();

            decrypted_values[0] == value && decrypted_values[1..].iter().all(|&v| v == 0)
        });

        assert!(flag);
    }
}

#[cfg(test)]
mod tests2 {
    use algebra::{ntt::NumberTheoryTransform, polynomial::FieldPolynomial, U64FieldEval};
    use rand::{distributions::Uniform, prelude::Distribution};

    use crate::RingSecretKeyType;

    use super::*;

    type FieldT = U64FieldEval<1125899906826241>;
    type ValT = <FieldT as Field>::ValueT; // inner type
    type PolyT = FieldPolynomial<FieldT>;

    const CIPHER_MODULUS: ValT = FieldT::MODULUS_VALUE; // ciphertext space
    const PLAIN_MODULUS: ValT = 4096; // message space

    const LOG_N: u32 = 11;
    const N: usize = 1 << LOG_N;

    #[inline]
    fn encode(m: ValT) -> ValT {
        (m as f64 * CIPHER_MODULUS as f64 / PLAIN_MODULUS as f64).round() as ValT
    }

    #[inline]
    fn decode(c: ValT) -> ValT {
        (c as f64 * PLAIN_MODULUS as f64 / CIPHER_MODULUS as f64).round() as ValT % PLAIN_MODULUS
    }

    // cargo test -r -p fhe_core --lib -- trace::tests2::test_expand_coeffs
    #[test]
    fn test_expand_coeffs() {
        let ntt_table = Arc::new(FieldT::generate_ntt_table(LOG_N).unwrap());

        let mut csrng = rand::thread_rng();

        let gaussian = DiscreteGaussian::new(0.0, 3.2, FieldT::MINUS_ONE).unwrap();
        let distr = Uniform::new(0, 2);

        let sk = RlweSecretKey::new(
            PolyT::random_ternary(N, &mut csrng),
            RingSecretKeyType::Ternary,
        );
        let ntt_sk = NttRlweSecretKey::from_coeff_secret_key(&sk, &ntt_table);

        let basis = NonPowOf2ApproxSignedBasis::new(FieldT::MODULUS_VALUE, 7, None);

        let trace_key = TraceKey::new(
            &sk,
            &ntt_sk,
            &basis,
            gaussian,
            Arc::clone(&ntt_table),
            &mut csrng,
        );

        let values: Vec<ValT> = distr.sample_iter(&mut csrng).take(N).collect();
        let encoded_values = PolyT::new(values.iter().copied().map(encode).collect());

        let mut cipher = <RlweCiphertext<FieldT>>::generate_random_zero_sample(
            &ntt_sk, gaussian, &ntt_table, &mut csrng,
        );
        *cipher.b_mut() += &encoded_values;

        let result = trace_key.expand_coefficients(&cipher);

        let flag = result.into_iter().zip(values).all(|(cipher, value)| {
            let a_mul_s =
                ntt_table.inverse_transform_inplace(ntt_table.transform(cipher.a()) * &*ntt_sk);
            let decrypted_values = (cipher.b() - a_mul_s)
                .into_iter()
                .map(decode)
                .collect::<Vec<ValT>>();

            decrypted_values[0] == value && decrypted_values[1..].iter().all(|&v| v == 0)
        });

        assert!(flag);
    }
}
