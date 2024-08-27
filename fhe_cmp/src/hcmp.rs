//! The implementation of homomorphic comparison.

use algebra::{AsInto, NTTField, Polynomial};
use fhe_core::{lwe_modulus_switch, LWEModulusType, Parameters, RLWEBlindRotationKey};
use lattice::{LWE, NTTRGSW, RLWE};

/// The struct of homomorphic comparision scheme.
pub struct HomCmpScheme<C: LWEModulusType, F: NTTField> {
    key: RLWEBlindRotationKey<F>,
    params: Parameters<C, F>,
    delta: F,
    half_delta: F,
}

impl<C: LWEModulusType, F: NTTField> HomCmpScheme<C, F> {
    /// Create a new instance.
    pub fn new(key: RLWEBlindRotationKey<F>, params: Parameters<C, F>) -> Self {
        let delta = F::lazy_new(
            (F::MODULUS_VALUE.as_into() / params.lwe_plain_modulus() as f64)
                .round()
                .as_into(),
        );
        let half_delta = F::lazy_new(
            (F::MODULUS_VALUE.as_into() / (params.lwe_plain_modulus() as f64 * 2.0))
                .round()
                .as_into(),
        );
        Self {
            key,
            params,
            delta,
            half_delta,
        }
    }

    /// Return a reference to the key.
    pub fn key(&self) -> &RLWEBlindRotationKey<F> {
        &self.key
    }

    /// Return a reference to the parameters.
    pub fn params(&self) -> &Parameters<C, F> {
        &self.params
    }

    /// Return delta.
    pub fn delta(&self) -> F {
        self.delta
    }

    /// Functional bootstrapping according to the test vector.
    ///
    /// # Arguments.
    ///
    /// * `ctxt` - The LWE ciphertext.
    /// * `test_vector` - The chosen test_vector.
    pub fn fbs(&self, ctxt: LWE<F>, test_vector: &[F]) -> LWE<F> {
        assert_eq!(self.params.ring_dimension(), test_vector.len());

        let switched_lwe = lwe_modulus_switch(
            ctxt,
            2 * self.params.ring_dimension() as u32,
            self.params.modulus_switch_round_method(),
        );

        let test_vector = Polynomial::from_slice(test_vector);

        self.key
            .blind_rotate(
                test_vector,
                &switched_lwe,
                self.params.blind_rotation_basis(),
            )
            .extract_lwe()
    }

    /// Performs the greater_than homomorphic comparison operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext with message `b`.
    /// * Output - An LWE ciphertext LWE(c), where c = 1 if  a > b; c = -1 otherwise.
    pub fn gt_hcmp(&self, c_rlwe: &RLWE<F>, c_rgsw: &NTTRGSW<F>) -> LWE<F> {
        let c = c_rlwe.mul_ntt_rgsw(c_rgsw);
        let test_poly = Polynomial::new(vec![F::neg_one(); self.params.ring_dimension()]);
        let c_a = c.a() * &test_poly;
        let c_b = c.b() * &test_poly;
        RLWE::new(c_a, c_b).extract_lwe()
    }

    /// Performs the less_than homomorphic operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext with message `b`.
    /// * Output - An LWE ciphertext LWE(c) where c = 1 if a < b; c = -1 otherwise.
    pub fn lt_hcmp(&self, c_rlwe: &RLWE<F>, c_rgsw: &NTTRGSW<F>) -> LWE<F> {
        let c = c_rlwe.mul_ntt_rgsw(c_rgsw);
        let mut test_poly = vec![F::one(); self.params.ring_dimension()];
        test_poly[0] = F::neg_one();
        let test_poly = Polynomial::new(test_poly);
        let c_a = c.a() * &test_poly;
        let c_b = c.b() * &test_poly;
        RLWE::new(c_a, c_b).extract_lwe()
    }

    /// Performs the equal homomorphic operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext with message `b`.
    /// * Output - An LWE ciphertext LWE(c), where c = 1 if  a == b; c = -1 otherwise.
    pub fn eq_hcmp(&self, c_rlwe: &RLWE<F>, c_rgsw: &NTTRGSW<F>) -> LWE<F> {
        let c = c_rlwe.mul_ntt_rgsw(c_rgsw);
        let mut c = c.extract_lwe();
        for elem in c.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *c.b_mut() = *c.b_mut() + *c.b_mut();
        *c.b_mut() -= self.delta;
        c
    }

    /// Performs the greater_than homomorphic operation of the two vectors of ciphertexts, where each vector of ciphertexts encrypt the bit chuncks of the message.
    ///
    /// # Arguments.
    ///
    /// `c_rlwe` - The vector of RLWE ciphertexts encrypting the bit chuncks of `a`.
    /// `c_rgsw` - The vector of RGSW ciphertexts encrypting the bit chuncks of `b`.
    /// Output - An LWE ciphertext LWE(c), where c = 1 if a > b, c = -1 otherwise.
    pub fn gt_arb_hcmp(&self, c_rlwe: &[RLWE<F>], c_rgsw: &[NTTRGSW<F>]) -> LWE<F> {
        todo!()
    }
}
