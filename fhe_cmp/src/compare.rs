use algebra::{
    transformation::MonomialNTT, AsInto, Field, FieldDiscreteGaussianSampler, NTTField,
    NTTPolynomial, Polynomial,
};
use fhe_core::{
    lwe_modulus_switch, LWEModulusType, Parameters, RLWEBlindRotationKey, SecretKeyPack,
};
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;

/// The struct of homomorphic comparison scheme.
pub struct HomomorphicCmpScheme<C: LWEModulusType, F: NTTField> {
    params: Parameters<C, F>,
    delta: F,
    half_delta: F,
    blind_rotation_key: RLWEBlindRotationKey<F>,
}

/// The struct of correlated homomorphic encryption scheme.
pub struct Encryptor<C: LWEModulusType, F: NTTField> {
    params: Parameters<C, F>,
    delta: F,
    error_sampler: FieldDiscreteGaussianSampler,
    ntt_ring_secret_key: NTTPolynomial<F>,
}

impl<C: LWEModulusType, F: NTTField> HomomorphicCmpScheme<C, F> {
    /// Create a new instance.
    pub fn new(key: &SecretKeyPack<C, F>) -> Self {
        let params = *key.parameters();
        let blind_rotation_key = RLWEBlindRotationKey::generate(key);
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
            params,
            delta,
            half_delta,
            blind_rotation_key,
        }
    }

    /// Return a reference to the key.
    pub fn blind_rotation_key(&self) -> &RLWEBlindRotationKey<F> {
        &self.blind_rotation_key
    }

    /// Return a reference to the parameters.
    pub fn params(&self) -> &Parameters<C, F> {
        &self.params
    }

    /// Return delta.
    pub fn delta(&self) -> F {
        self.delta
    }

    /// Return half_delta.
    pub fn half_delta(&self) -> F {
        self.half_delta
    }

    /// Functional bootstrapping according to the test vector.
    ///
    /// # Arguments.
    ///
    /// * `ctxt` - The LWE ciphertext.
    /// * `test_vector` - The chosen test_vector.
    fn fbs(&self, ctxt: LWE<F>, test_vector: Polynomial<F>) -> LWE<F> {
        assert_eq!(self.params.ring_dimension(), test_vector.coeff_count());

        let switched_lwe = lwe_modulus_switch(
            ctxt,
            2 * self.params.ring_dimension() as u32,
            self.params.modulus_switch_round_method(),
        );

        self.blind_rotation_key
            .blind_rotate(
                test_vector,
                &switched_lwe,
                self.params.blind_rotation_basis(),
            )
            .extract_lwe_locally()
    }

    /// Homomorphic and operation in comparison.
    ///
    /// # Arguments
    ///
    /// * `ca` - The LWE ciphertext `ca`, with message `a`.
    /// * `cb` - The LWE ciphertext `cb`, with message `b`.
    /// * Output - An LWE ciphertext LWE(c), only returns delta when both the values of a and b are delta, else -delta.
    pub fn homand(&self, ca: &LWE<F>, cb: &LWE<F>) -> LWE<F> {
        let mut temp = ca.add_component_wise_ref(cb);
        *temp.b_mut() -= self.delta;

        let ring_dimension = self.params.ring_dimension();
        let x = ring_dimension >> 3;
        let y = x + ring_dimension >> 2;
        let z = x + ring_dimension >> 1;
        let u = ring_dimension - x;

        let mut test = Polynomial::zero(ring_dimension);
        test[x..y].iter_mut().for_each(|v| *v = self.delta);
        test[z..u].iter_mut().for_each(|v| *v = self.delta);

        self.fbs(temp, test)
    }

    /// Performs the greater_than homomorphic comparison operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext with message `b`.
    /// * Output - An LWE ciphertext LWE(c), where c = 1 if  a > b; c = -1 otherwise.
    pub fn gt_hcmp(&self, c_rlwe: &RLWE<F>, c_rgsw: &NTTRGSW<F>) -> LWE<F> {
        let test_poly =
            Polynomial::new(vec![F::neg_one(); self.params.ring_dimension()]).into_ntt_polynomial();

        let c_rlwe_clone = c_rlwe.clone();
        let (a, b) = c_rlwe_clone.given_a_b();
        let c_a = a * &test_poly;
        let c_b = b * &test_poly;

        RLWE::new(c_a, c_b)
            .mul_ntt_rgsw(c_rgsw)
            .extract_lwe_locally()
    }

    /// Performs the greater_than homomorphic comparison operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext vector with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext vector with message `b`.
    /// * Output - An LWE ciphertext LWE(c), where c = 1 if  a > b; c = -1 otherwise.
    pub fn gt_arbhcmp(&self, c_rlwe: &[RLWE<F>], c_rgsw: &[NTTRGSW<F>]) -> LWE<F> {
        let len = c_rlwe.len();
        assert_eq!(len, c_rgsw.len());
        assert!(len > 0);
        //for the first digit in two vectors
        let hcmp = self.gt_hcmp(&c_rlwe[0], &c_rgsw[0]);
        //for the other multi digits in the two vector
        let mut res = hcmp;
        for i in 1..len {
            // Evaluate lower digits comparison
            // low_part_gt_res = ciphers1[0: cipher_size - 1] > ciphers2[0: cipher_size - 1]
            // low_part_gt_res = delta (true) or -delta (false)
            let low_part_gt_res = res;

            // Evaluate the highest digit comparison
            // eq_res = ciphers1[cipher_size - 1] == ciphers2[cipher_size - 1]
            // eq_res = delta (true) or 0 (false)
            let eq_res = c_rlwe[i].mul_ntt_rgsw(&c_rgsw[i]).extract_lwe_locally();

            // Evaluate the highest digit comparison
            // high_res = ciphers1[cipher_size - 1] > ciphers2[cipher_size - 1]
            // high_res = delta (true)  or -delta (false)
            let gt_res = self.gt_hcmp(&c_rlwe[i], &c_rgsw[i]);

            /*
            Start GateMUX, this is an optimized-version of GateMUX, not general version of GateMUX in the paper.
            Evaluate a linear transformation of the low_res, equal_res, high_res
            new_lwe = equal_res + 2 * high_res + low_res + delta/2
            Mux function: equal_res ? high_res : low_res

            Eight case:
                equal_res = 0, high_res = -delta, low_res = -delta --> new_lwe = -5delta/2, expect_compare_res = false
                equal_res = 0, high_res = -delta, low_res =  delta --> new_lwe = -1delta/2, expect_compare_res = false
                equal_res = 0, high_res =  delta, low_res = -delta --> new_lwe =  3delta/2, expect_compare_res = true
                equal_res = 0, high_res =  delta, low_res =  delta --> new_lwe =  7delta/2, expect_compare_res = true
                equal_res = delta, high_res = -delta, low_res = -delta --> new_lwe = -3delta/2, expect_compare_res = false
                equal_res = delta, high_res = -delta, low_res =  delta --> new_lwe =  1delta/2, expect_compare_res = true
                equal_res = delta, high_res =  delta, low_res = -delta --> Does not exist
                equal_res = delta, high_res =  delta, low_res =  delta --> Does not exist

            Based on the above,
            if new_lwe < 0, expect_compare_res = false
            if new_lwe > 0, expect_compare_res = true
            */
            let mut new_lwe = eq_res
                .add_component_wise(&gt_res)
                .add_component_wise(&gt_res)
                .add_component_wise(&low_part_gt_res);
            *new_lwe.b_mut() += self.half_delta;
            /*
            Start gate bootstrapping, test_vector = delta + delta*X + ... + delta*X^{n-1}
            If new_lwe < 0, expect_compare_res = false, and the test_vector right shift, the function outputs -delta
            If new_lwe > 0, expect_compare_res = true,  and the test_vector left  shift, the function outputs  delta
            */
            let test = vec![self.delta; self.params.ring_dimension()];
            res = self.fbs(new_lwe, Polynomial::new(test));
        }
        res
    }

    /// Performs the equal homomorphic operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext with message `b`.
    /// * Output - An LWE ciphertext LWE(c), where c = 1 if  a == b; c = -1 otherwise.
    pub fn eq_hcmp(&self, c_rlwe: &RLWE<F>, c_rgsw: &NTTRGSW<F>) -> LWE<F> {
        let mut c = c_rlwe.mul_ntt_rgsw(c_rgsw).extract_lwe_locally();
        for elem in c.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *c.b_mut() = c.b() + c.b() - self.delta;
        c
    }

    /// Performs the equal homomorphic operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext vector with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext vector with message `b`.
    /// * Output - An LWE ciphertext LWE(c), where c = 1 if  a == b; c = -1 otherwise.
    pub fn eq_arbhcmp(&self, c_rlwe: &[RLWE<F>], c_rgsw: &[NTTRGSW<F>]) -> LWE<F> {
        let len = c_rlwe.len();
        assert_eq!(len, c_rgsw.len());
        assert!(len > 0);

        // the comparison result of the first digit
        let hcmp = self.eq_hcmp(&c_rlwe[0], &c_rgsw[0]);

        // the comparison result of the other digit
        c_rlwe[1..]
            .iter()
            .zip(&c_rgsw[1..])
            .fold(hcmp, |low_res, (r, g)| {
                let gt_res = self.eq_hcmp(r, g);
                self.homand(&low_res, &gt_res)
            })
    }

    /// Performs the less_than homomorphic operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext with message `b`.
    /// * Output - An LWE ciphertext LWE(c) where c = 1 if a < b; c = -1 otherwise.
    pub fn lt_hcmp(&self, c_rlwe: &RLWE<F>, c_rgsw: &NTTRGSW<F>) -> LWE<F> {
        let mut test_poly = vec![F::one(); self.params.ring_dimension()];
        test_poly[0] = F::neg_one();
        let test_poly = Polynomial::new(test_poly).into_ntt_polynomial();

        let (a, b) = c_rlwe.clone().given_a_b();

        let c_a = a * &test_poly;
        let c_b = b * &test_poly;

        RLWE::new(c_a, c_b)
            .mul_ntt_rgsw(c_rgsw)
            .extract_lwe_locally()
    }

    /// Performs the less_than homomorphic operation of two ciphertexts.
    ///
    /// # Arguments.
    ///
    /// * `c_rlwe` - The RLWE ciphertext vector with message `a`.
    /// * `c_rgsw` - The NTTRGSW ciphertext vector with message `b`.
    /// * Output - An LWE ciphertext LWE(c) where c = 1 if a < b; c = -1 otherwise.
    pub fn lt_arbhcmp(&self, c_rlwe: &[RLWE<F>], c_rgsw: &[NTTRGSW<F>]) -> LWE<F> {
        let len = c_rlwe.len();
        assert_eq!(len, c_rgsw.len());
        assert!(len > 0);

        // Vector contains only one element
        let hcmp = self.lt_hcmp(&c_rlwe[0], &c_rgsw[0]);
        let mut res = hcmp;
        for i in 1..len {
            // Evaluate lower digits comparison
            // low_part_gt_res = ciphers1[0: cipher_size - 1] < ciphers2[0: cipher_size - 1]
            // low_part_gt_res = delta (true) or -delta (false)
            let low_part_gt_res = res;

            // Evaluate the highest digit comparison
            // equal_res = ciphers1[cipher_size - 1] == ciphers2[cipher_size - 1]
            // equal_res = delta (true) or 0 (false)
            let eq_res = c_rlwe[i].mul_ntt_rgsw(&c_rgsw[i]).extract_lwe_locally();

            // Evaluate the highest digit comparison
            // high_res = ciphers1[cipher_size - 1] < ciphers2[cipher_size - 1]
            // high_res = delta or -delta
            let gt_res = self.lt_hcmp(&c_rlwe[i], &c_rgsw[i]);

            /*
            Start GateMUX, this is an optimized-version of GateMUX, not general version of GateMUX in the paper.
            Evaluate a linear transformation of the low_res, equal_res, high_res
            new_lwe = equal_res + 2 * high_res + low_res + delta/2
            Mux function: equal_res ? high_res : low_res

            Eight case:
                equal_res = 0, high_res = -delta, low_res = -delta --> new_lwe = -5delta/2, expect_compare_res = false
                equal_res = 0, high_res = -delta, low_res =  delta --> new_lwe = -1delta/2, expect_compare_res = false
                equal_res = 0, high_res =  delta, low_res = -delta --> new_lwe =  3delta/2, expect_compare_res = true
                equal_res = 0, high_res =  delta, low_res =  delta --> new_lwe =  7delta/2, expect_compare_res = true
                equal_res = delta, high_res = -delta, low_res = -delta --> new_lwe = -3delta/2, expect_compare_res = false
                equal_res = delta, high_res = -delta, low_res =  delta --> new_lwe =  1delta/2, expect_compare_res = true
                equal_res = delta, high_res =  delta, low_res = -delta --> Does not exist
                equal_res = delta, high_res =  delta, low_res =  delta --> Does not exist

            Based on the above,
            if new_lwe > 0, expect_compare_res = true
            if new_lwe < 0, expect_compare_res = false
            */
            let mut new_lwe = eq_res
                .add_component_wise(&gt_res)
                .add_component_wise(&gt_res)
                .add_component_wise(&low_part_gt_res);
            *new_lwe.b_mut() += self.half_delta;
            let test = vec![self.delta; self.params.ring_dimension()];
            /*
            Start gate bootstrapping, test_vector = delta + deltaX + ... + deltaX^{n-1}
            If new_lwe < 0, expect_compare_res = false, and the test_vector right shift, the function outputs -delta
            If new_lwe > 0, expect_compare_res = true,  and the test_vector left  shift, the function outputs  delta
            */
            res = self.fbs(new_lwe, Polynomial::new(test))
        }
        res
    }
}

impl<C: LWEModulusType, F: NTTField> Encryptor<C, F> {
    /// Create a new encryptor instance.
    pub fn new(secret_key: &SecretKeyPack<C, F>) -> Self {
        let ntt_ring_secret_key = secret_key.ntt_ring_secret_key().clone();
        let params = *secret_key.parameters();
        let error_sampler = params.ring_noise_distribution();
        let delta = F::lazy_new(
            (F::MODULUS_VALUE.as_into() / params.lwe_plain_modulus() as f64)
                .round()
                .as_into(),
        );
        Self {
            params,
            ntt_ring_secret_key,
            error_sampler,
            delta,
        }
    }

    /// Return a reference to the parameter.
    pub fn params(&self) -> &Parameters<C, F> {
        &self.params
    }

    /// Return a reference to the ring secret key.
    pub fn ntt_ring_secret_key(&self) -> &NTTPolynomial<F> {
        &self.ntt_ring_secret_key
    }

    /// Return error sampler
    pub fn error_sampler(&self) -> FieldDiscreteGaussianSampler {
        self.error_sampler
    }

    /// Return delta
    pub fn delta(&self) -> F {
        self.delta
    }

    /// Performs the encryption to rlwe ciphertext of a number.
    ///
    /// # Arguments.
    ///
    /// * `num` - The number to be encrypted with message `a`.
    /// * `rng` - The random value used for encryption.
    /// * Output - An RLWE ciphertext vector RLWE(a).
    pub fn rlwe_encrypt<R: CryptoRng + Rng>(&self, mut num: usize, mut rng: R) -> Vec<RLWE<F>> {
        let key = &self.ntt_ring_secret_key;
        let ring_dimension = key.coeff_count();
        let trailing_zeros = ring_dimension.trailing_zeros();
        let mask = ring_dimension - 1;
        let mut num_vec = Vec::new();
        while num != 0 {
            num_vec.push(num & mask);
            num >>= trailing_zeros;
        }
        self.rlwe_values(&num_vec, &mut rng)
    }

    /// Performs the encryption to nttrgsw ciphertext vector of a number.
    ///
    /// # Arguments.
    ///
    /// * `num` - The number to be encrypted with message `a`.
    /// * `rng` - The random value used for encryption.
    /// * Output - An NTTRGSW ciphertext vector NTTRGSW(a).
    pub fn rgsw_encrypt<R: CryptoRng + Rng>(&self, mut num: usize, mut rng: R) -> Vec<NTTRGSW<F>> {
        let key = &self.ntt_ring_secret_key;
        let ring_dimension = key.coeff_count();
        let trailing_zeros = ring_dimension.trailing_zeros();
        let mask = ring_dimension - 1;
        let mut num_vec = Vec::new();
        while num != 0 {
            num_vec.push(num & mask);
            num >>= trailing_zeros;
        }
        self.rgsw_values(&num_vec, &mut rng)
    }

    /// Performs the generation of ciphertext to nttrgsw ciphertext vector of a number that has been divided into a vector.
    ///
    /// # Arguments.
    ///
    /// * `values` - The vector to be encrypted with message `a`.
    /// * `rng` - The random value used for encryption.
    /// * Output - An NTTRGSW ciphertext vector NTTRGSW(a).
    fn rgsw_values<R: CryptoRng + Rng>(&self, values: &[usize], mut rng: R) -> Vec<NTTRGSW<F>> {
        let len = values.len();
        let mut res = Vec::with_capacity(len);
        let basis = self.params.blind_rotation_basis();
        for &v in values {
            let mut rgsw = NTTRGSW::generate_random_zero_sample(
                &self.ntt_ring_secret_key,
                basis,
                self.error_sampler,
                &mut rng,
            );
            self.ntt_rgsw_turn(&mut rgsw, v);
            res.push(rgsw);
        }
        res
    }

    /// Performs the generation of ciphertext to rlwe ciphertext vector of a number that has been divided into a vector.
    ///
    /// # Arguments.
    ///
    /// * `values` - The vector to be encrypted with message `a`.
    /// * `rng` - The random value used for encryption.
    /// * Output - An RLWE ciphertext vector RLWE(a).
    fn rlwe_values<R: CryptoRng + Rng>(&self, values: &[usize], mut rng: R) -> Vec<RLWE<F>> {
        let len = values.len();
        let mut res = Vec::with_capacity(len);
        for &v in values {
            let mut rlwe = RLWE::generate_random_zero_sample(
                &self.ntt_ring_secret_key,
                self.error_sampler,
                &mut rng,
            );
            rlwe.b_mut()[0] += self.delta;
            Self::rlwe_turn(&mut rlwe, v);
            res.push(rlwe)
        }
        res
    }

    /// Performs the alignment of the rlwe ciphertext vector and the nttrgsw ciphertext vector
    ///
    /// # Arguments.
    ///
    /// * `cipher1` - The RLWE ciphertext vector.
    /// * `cipher2` - The NTTRGSW ciphertext vector.
    /// * Output - The two ciphertexts which have the same number of elements in vectors.
    pub fn align<R: CryptoRng + Rng>(
        &self,
        cipher1: &mut Vec<RLWE<F>>,
        cipher2: &mut Vec<NTTRGSW<F>>,
        mut rng: R,
    ) {
        let len1 = cipher1.len();
        let len2 = cipher2.len();
        match len1.cmp(&len2) {
            std::cmp::Ordering::Greater => {
                cipher2.resize_with(len1, || {
                    NTTRGSW::generate_random_one_sample(
                        &self.ntt_ring_secret_key,
                        self.params.blind_rotation_basis(),
                        self.error_sampler,
                        &mut rng,
                    )
                });
            }
            std::cmp::Ordering::Equal => (),
            std::cmp::Ordering::Less => {
                cipher1.resize_with(len2, || {
                    let mut rlwe = RLWE::generate_random_zero_sample(
                        &self.ntt_ring_secret_key,
                        self.error_sampler,
                        &mut rng,
                    );
                    rlwe.b_mut()[0] += self.delta;
                    rlwe
                });
            }
        }
    }

    /// Performs the rotation of rlwe ciphertext.
    ///
    /// # Arguments.
    ///
    /// * `ciphertext` - The rlwe ciphertext to be turned with message `a`.
    /// * `num` - The times that the ciphertext will be rotated.
    /// * Output - An RLWE ciphertext RLWE(a * X^num).
    fn rlwe_turn(ciphertext: &mut RLWE<F>, num: usize) {
        let (a, b) = ciphertext.a_b_mut_slices();
        a.rotate_right(num);
        b.rotate_right(num);
        for elem in &mut a[..num] {
            *elem = -*elem;
        }
        for elem in &mut b[..num] {
            *elem = -*elem;
        }
    }

    /// Performs the rotation of nttrgsw ciphertext.
    ///
    /// # Arguments.
    ///
    /// * `ciphertext` - The nttrgsw ciphertext to be turned with message `a`.
    /// * `num` - The times that the ciphertext will be rotated.
    /// * Output - An NTTRGSW ciphertext NTTRGSW(a * X^-num).
    fn ntt_rgsw_turn(&self, ciphertext: &mut NTTRGSW<F>, num: usize) {
        let ring_dimension = self.params.ring_dimension();
        let basis = self.params.blind_rotation_basis();

        let neg_num = if num != 0 {
            (ring_dimension << 1) - num
        } else {
            0
        };

        let mut poly = NTTPolynomial::zero(ring_dimension);
        let ntt_table = F::get_ntt_table(ring_dimension.trailing_zeros()).unwrap();
        ntt_table.transform_coeff_one_monomial(neg_num, poly.as_mut_slice());

        let scalar = F::lazy_new(basis.basis());

        let (c_m_mut, c_neg_s_m_mut) = ciphertext.two_parts_mut();

        c_neg_s_m_mut
            .iter_mut()
            .zip(c_m_mut.iter_mut())
            .for_each(|(neg_s_m, m)| {
                *neg_s_m.a_mut() += &poly;
                *m.b_mut() += &poly;
                poly.mul_scalar_assign(scalar);
            });
    }
}

/// Performs the decryption operation.
pub fn decrypt<F: Field<Value = u64> + NTTField>(sk: &[F], ciphertext: LWE<F>) -> u64 {
    let a_mul_s = ciphertext
        .a()
        .iter()
        .zip(sk)
        .fold(F::zero(), |acc, (&s, &a)| acc.add_mul(s, a));
    decode(ciphertext.b() - a_mul_s)
}

/// Performs the operation turning an encoded value to its real number.
pub fn decode<F: Field<Value = u64> + NTTField>(c: F) -> u64 {
    (c.value() as f64 * 8_f64 / F::MODULUS_VALUE as f64).round() as u64 % 8
}
