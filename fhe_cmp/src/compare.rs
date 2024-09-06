use algebra::{
    transformation::MonomialNTT, AsInto, Basis, Field, FieldDiscreteGaussianSampler, NTTField,
    NTTPolynomial, Polynomial,
};
use fhe_core::{lwe_modulus_switch, LWEModulusType, Parameters, RLWEBlindRotationKey};
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;

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

    /// Performs the homomorphic and operation.
    ///
    /// # Arguments
    ///
    /// * Input: blind rotation key `self`.
    /// * Input: LWE ciphertext `ca`, with message `a`.
    /// * Input: LWE ciphertext `cb`, with message `b`.
    /// * Input: the size of test vector `poly_length`.
    /// * Input:  delta - plain_modulus / 8.
    /// * Output: LWE ciphertext with message `a & b`.
    /// homand takes two input ca and cb, only when ca = cb = delta will the output be delta otherwise will be -delta
    /// test_vector for gatebootstrapping = delta + delta*X + ... + delta*X^{n-1}
    /// posible cases:
    /// ca = delta cb = delta      temp = 2 * delta - delta = delta > 0
    /// ca = delta cb = -delta     temp = 0 - delta = -delta < 0
    /// ca = -delta cb = delta     temp = 0 - delta = -delta < 0
    /// ca = -delta cb = -delta    temp = -2 * delta - delta = -3  * delta < 0
    /// other cases don't exist
    /// If temp > 0, expect_compare_res = true, and the test_vector left shift, the function outputs delta
    /// If temp < 0, expect_compare_res = false,  and the test_vector right shift, the function outputs -delta

    pub fn homand(&self, ca: &LWE<F>, cb: &LWE<F>, poly_length: usize, delta: F) -> LWE<F> {
        let mut temp = ca.add_component_wise_ref(cb);
        *temp.b_mut() = temp.b() - delta;
        let mut test = vec![F::zero(); poly_length];
        let mu = delta;
        test.iter_mut().for_each(|v| *v = mu);
        self.fbs(temp, &test)
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

    /// Performs the homomorphic comparison "greater" operation of two encoded numbers which have been transformed to vectors.
    ///
    /// # Arguments
    ///
    /// * Input: BlindRotationKey `self`.
    /// * Input: RLWE ciphertext vector `cipher1`, with message `a`.
    /// * Input: NTTRGSW ciphertext vector `cipher2`, with message `b`.
    /// * Input: delta = plain_modulus / 8. (plain_modulus stands for ring_modulus)
    /// * Input: half_delta = plain_modulus / 16. (plain_modulus stands for ring_modulus)
    /// * Input: the size of RLWE and NTTRGSW vector `poly_length`.
    /// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2,otherwise c=-1.
    pub fn gt_arbhcmp(
        &self,
        cipher1: &[RLWE<F>],
        cipher2: &[NTTRGSW<F>],
        delta: F,
        half_delta: F,
        poly_length: usize,
    ) -> LWE<F> {
        let len = cipher1.len();
        assert_eq!(len, cipher2.len());
        assert!(len > 0);
        //for the first digit in two vectors
        let hcmp = self.gt_hcmp(&cipher1[0], &cipher2[0]);
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
            let eq_res = cipher1[i]
                .mul_ntt_rgsw(&cipher2[i])
                .extract_lwe_locally()
                .clone();
            // Evaluate the highest digit comparison
            // high_res = ciphers1[cipher_size - 1] > ciphers2[cipher_size - 1]
            // high_res = delta (true)  or -delta (false)
            let mut gt_res = self.gt_hcmp(&cipher1[i], &cipher2[i]);
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
            for elem in gt_res.a_mut().iter_mut() {
                *elem = *elem + *elem;
            }
            *gt_res.b_mut() = gt_res.b() + gt_res.b();
            let mut new_lwe = eq_res
                .add_component_wise(&low_part_gt_res)
                .add_component_wise(&gt_res);
            *new_lwe.b_mut() = new_lwe.b() + half_delta;
            /*
            Start gate boostrapping, test_vector = delta + delta*X + ... + delta*X^{n-1}
            If new_lwe < 0, expect_compare_res = false, and the test_vector right shift, the function outputs -delta
            If new_lwe > 0, expect_compare_res = true,  and the test_vector left  shift, the function outputs  delta
            */
            let mut test = vec![F::zero(); poly_length];
            let mu = delta;
            test.iter_mut().for_each(|v| *v = mu);
            res = self.fbs(new_lwe, &test);
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
        let c = c_rlwe.mul_ntt_rgsw(c_rgsw);
        let mut c = c.extract_lwe();
        for elem in c.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *c.b_mut() = *c.b_mut() + *c.b_mut();
        *c.b_mut() -= self.delta;
        c
    }

    /// Performs the homomorphic comparison "equality" operation of two encoded numbers.
    ///
    /// # Arguments
    ///
    /// * Input: BlindRotationKey `self`.
    /// * Input: RLWE ciphertext vector `cipher1`, with message `a`.
    /// * Input: NTTRGSW ciphertext vector `cipher2`, with message `b`.
    /// * Input: the size of RLWE and RGSW vector `poly_length`.
    /// * Input: delta = plain_modulus / 8. (plain_modulus stands for ring_modulus)
    /// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=-1.
    pub fn eq_arbhcmp(
        &self,
        cipher1: &[RLWE<F>],
        cipher2: &[NTTRGSW<F>],
        poly_length: usize,
        delta: F,
    ) -> LWE<F> {
        let len = cipher1.len();
        assert_eq!(len, cipher2.len());
        assert!(len > 0);
        // the comparison result of the first digit
        let hcmp = self.eq_hcmp(&cipher1[0], &cipher2[0]);
        // the comparison result of the other digit
        let mut res = hcmp;
        for i in 1..len {
            //only when low_res = delta and gt_res = delta, the res will be delta, otherwise res will be -delta
            let low_res = res;
            let gt_res = self.eq_hcmp(&cipher1[i], &cipher2[i]);
            res = self.homand(&low_res, &gt_res, poly_length, delta);
        }
        res
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

    /// Performs the homomorphic comparison "less" operation of two encoded numbers.
    ///
    /// # Arguments
    ///
    /// * Input: BlindRotationKey `self`.
    /// * Input: RLWE ciphertext vector `cipher1`, with message `a`.
    /// * Input: NTTRGSW ciphertext vector `cipher2`, with message `b`.
    /// * Input: delta = plain_modulus / 8.
    /// * Input: half_delta = plain_modulus / 16.
    /// * Input: the size of RLWE and RGSW vector `poly_length`.
    /// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=-1.
    pub fn lt_arbhcmp(
        &self,
        cipher1: &[RLWE<F>],
        cipher2: &[NTTRGSW<F>],
        delta: F,
        half_delta: F,
        poly_length: usize,
    ) -> LWE<F> {
        let len = cipher1.len();
        assert_eq!(len, cipher2.len());
        assert!(len > 0);
        // Vector contains only one element
        let hcmp = self.lt_hcmp(&cipher1[0], &cipher2[0]);
        let mut res = hcmp;
        for i in 1..len {
            // Evaluate lower digits comparison
            // low_part_gt_res = ciphers1[0: cipher_size - 1] < ciphers2[0: cipher_size - 1]
            // low_part_gt_res = delta (true) or -delta (false)
            let low_part_gt_res = res;
            // Evaluate the highest digit comparison
            // equal_res = ciphers1[cipher_size - 1] == ciphers2[cipher_size - 1]
            // equal_res = delta (true) or 0 (false)
            let eq_res = cipher1[i]
                .mul_ntt_rgsw(&cipher2[i])
                .extract_lwe_locally()
                .clone();
            // Evaluate the highest digit comparison
            // high_res = ciphers1[cipher_size - 1] < ciphers2[cipher_size - 1]
            // high_res = delta or -delta
            let mut gt_res = self.lt_hcmp(&cipher1[i], &cipher2[i]);
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
            for elem in gt_res.a_mut().iter_mut() {
                *elem = *elem + *elem;
            }
            *gt_res.b_mut() = gt_res.b() + gt_res.b();
            let mut new_lwe = eq_res
                .add_component_wise(&low_part_gt_res)
                .add_component_wise(&gt_res);
            *new_lwe.b_mut() = new_lwe.b() + half_delta;
            let mut test = vec![F::zero(); poly_length];
            let mu = delta;
            test.iter_mut().for_each(|v| *v = mu);
            /*
            Start gate boostrapping, test_vector = delta + deltaX + ... + deltaX^{n-1}
            If new_lwe < 0, expect_compare_res = false, and the test_vector right shift, the function outputs -delta
            If new_lwe > 0, expect_compare_res = true,  and the test_vector left  shift, the function outputs  delta
            */
            res = self.fbs(new_lwe, &test)
        }
        res
    }
}

/// Performing the initialization, encrypting 2 numbers to their corresponding ciphertext
///
/// # Arguments
///
/// * Input: input number `num1`.
/// * Input: input number `num2`.
/// * Input: encryption key `ntt_ring_secret_key`.
/// * Input: This basis used for decomposition of the field `basis`.
/// * Input: The encryption of 1 `delta`.
/// * Input: sampler used for generating random number `error_sampler`.
/// * Input: method used for generating random number `rng`.
/// * Output: RLWE vector as the encryption of num1, NTTRGSW vector as the encryption of the encryption of num2.
pub fn encrypt<F, R>(
    mut num1: usize,
    mut num2: usize,
    ntt_ring_secret_key: &NTTPolynomial<F>,
    basis: Basis<F>,
    delta: F,
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> (Vec<RLWE<F>>, Vec<NTTRGSW<F>>)
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let ring_dimension = ntt_ring_secret_key.coeff_count();
    let trailing_zeros = ring_dimension.trailing_zeros();
    let mask = ring_dimension - 1;
    let mut num1_vec = Vec::new();
    let mut num2_vec = Vec::new();
    while num1 != 0 {
        num1_vec.push(num1 & mask);
        num1 >>= trailing_zeros;
    }
    while num2 != 0 {
        num2_vec.push(num2 & mask);
        num2 >>= trailing_zeros;
    }
    let len = num1_vec.len().max(num2_vec.len()).max(1);
    num1_vec.resize(len, 0);
    num2_vec.resize(len, 0);
    let vec1 = rlwe_values(
        &num1_vec,
        ntt_ring_secret_key,
        delta,
        error_sampler,
        &mut rng,
    );
    let vec2 = rgsw_values(
        &num2_vec,
        ntt_ring_secret_key,
        basis,
        error_sampler,
        &mut rng,
    );
    (vec1, vec2)
}

/// decryption for the ciphertext
pub fn decrypt<F: Field<Value = u64> + NTTField>(sk: &[F], ciphertext: LWE<F>) -> u64 {
    let a_mul_s = sk
        .iter()
        .zip(ciphertext.a())
        .fold(F::zero(), |acc, (&s, &a)| acc + s * a);
    decode(ciphertext.b() - a_mul_s)
}

/// Peforms the operation turning a value to its real number
pub fn decode<F: Field<Value = u64> + NTTField>(c: F) -> u64 {
    (c.value() as f64 * 8_f64 / 132120577_f64).round() as u64 % 8
}

/// Performs the operation of turning a vector to the corresponding NTTRGSW ciphertext.
///
/// # Arguments
///
/// * Input: vector `values`.
/// * Input: encryption key `ntt_ring_secret_key`.
/// * Input: This basis used for decomposition of the field `basis`.
/// * Input: sampler used for generating random number `error_sampler`.
/// * Input: method used for generating random number `rng`.
/// * Output:corresponding NTTRGSW ciphertext X^values.
fn rgsw_values<F, R>(
    values: &[usize],
    ntt_ring_secret_key: &NTTPolynomial<F>,
    basis: Basis<F>,
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> Vec<NTTRGSW<F>>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let ring_dimension = ntt_ring_secret_key.coeff_count();
    let len = values.len();
    let mut res = Vec::with_capacity(len);
    for &v in values {
        let mut rgsw = NTTRGSW::generate_random_zero_sample(
            ntt_ring_secret_key,
            basis,
            error_sampler,
            &mut rng,
        );
        ntt_rgsw_turn(&mut rgsw, v, ring_dimension, basis);
        res.push(rgsw);
    }
    res
}

/// Performs the operation of turning a vector to the corresponding RLWE ciphertext.
///
/// # Arguments
///
/// * Input: vector `values`.
/// * Input: encryption key `ntt_ring_secret_key`.
/// * Input: The encryption of 1 `delta`.
/// * Input: sampler used for generating random number `error_sampler`.
/// * Input: method used for generating random number `rng`.
/// * Output:corresponding RLWE ciphertext X^(-values).
fn rlwe_values<F, R>(
    values: &[usize],
    ntt_ring_secret_key: &NTTPolynomial<F>,
    delta: F,
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
) -> Vec<RLWE<F>>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let len = values.len();
    let mut res = Vec::with_capacity(len);
    for &v in values {
        let mut rlwe =
            RLWE::generate_random_zero_sample(ntt_ring_secret_key, error_sampler, &mut rng);
        rlwe.b_mut()[0] += delta;
        rlwe_turn(&mut rlwe, v);
        res.push(rlwe)
    }
    res
}

/// Performs the RLWE rotation operation.
///
/// # Arguments
///
/// * Input: RLWE ciphertext `ciphertext`.
/// * Input: usize number `num`.
/// * Output:RLWE ciphertext `ciphertext*x^num`.
pub fn rlwe_turn<F: NTTField>(ciphertext: &mut RLWE<F>, num: usize) {
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

/// Performs the NTTRGSW rotation operation.
///
/// # Arguments
///
/// * Input: NTTRGSW ciphertext `ciphertext`.
/// * Input: usize number `num`.
/// * Input: the size of NTTRGSW vector `poly_length`.
/// * Output:RGSW ciphertext `ciphertext*x^(-num)`.
pub fn ntt_rgsw_turn<F: NTTField>(
    ciphertext: &mut NTTRGSW<F>,
    num: usize,
    ring_dimension: usize,
    basis: Basis<F>,
) {
    let neg_num = if num != 0 {
        (ring_dimension << 1) - num
    } else {
        0
    };
    let mut poly = NTTPolynomial::new(vec![F::zero(); ring_dimension]);
    let ntt_table = F::get_ntt_table(ring_dimension.trailing_zeros()).unwrap();
    ntt_table.transform_coeff_one_monomial(neg_num, poly.as_mut_slice());
    let mut poly_c = poly.clone();
    ciphertext.c_neg_s_m_mut().iter_mut().for_each(|rlwe| {
        *rlwe.a_mut() += &poly;
        poly.mul_scalar_assign(F::lazy_new(basis.basis()));
    });
    ciphertext.c_m_mut().iter_mut().for_each(|rlwe| {
        *rlwe.b_mut() += &poly_c;
        poly_c.mul_scalar_assign(F::lazy_new(basis.basis()));
    });
}
