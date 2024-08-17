//!

use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    modulus::PowOf2Modulus,
    transformation::MonomialNTT,
    Basis, Field, FieldDiscreteGaussianSampler, NTTField, NTTPolynomial, Polynomial,
};
use fhe_core::{
    lwe_modulus_switch, BlindRotationType, ConstParameters, ModulusSwitchRoundMethod, Parameters,
    RLWEBlindRotationKey, RingSecretKeyType, SecretKeyType, StepsAfterBR,
};
use lattice::{LWE, NTTRGSW, RGSW, RLWE};
use once_cell::sync::Lazy;
use rand::prelude::*;

///default size
#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct DefaultField(pub u64);

/// inner type
pub type Inner = u64;
/// ciphertext space
pub const FP: Inner = DefaultField::MODULUS_VALUE;
/// message space
pub const FT: Inner = 16;
///encode of 1
pub const DEELTA: DefaultField = DefaultField((FP as f64 / FT as f64) as Inner);
///encode of 1/2
pub const HALF_DEELTA: DefaultField = DefaultField((FP as f64 / (FT as f64 * 2.0)) as Inner);

/// Default 128-bits security Parameters
pub static DEFAULT_PARAMERTERS: Lazy<Parameters<u64, DefaultField>> = Lazy::new(|| {
    Parameters::<u64, DefaultField>::new(ConstParameters {
        lwe_dimension: 1024,
        lwe_modulus: 2048,
        t: 16,
        lwe_noise_std_dev: 3.20,
        secret_key_type: SecretKeyType::Binary,
        blind_rotation_type: BlindRotationType::RLWE,
        ring_dimension: 1024,
        ring_modulus: 132120577,
        ring_noise_std_dev: 3.20 * ((1 << 1) as f64),
        ring_secret_key_type: RingSecretKeyType::Binary,
        blind_rotation_basis_bits: 1,
        steps_after_blind_rotation: StepsAfterBR::Ms,
        key_switching_basis_bits: 1,
        key_switching_std_dev: 3.2 * ((1 << 1) as f64),
        modulus_switcing_round_method: ModulusSwitchRoundMethod::Round,
    })
    .unwrap()
});

/// Performs the initialization, turning 2 numbers to their corresponding ciphertext
pub fn initial<F, R>(
    mut num1: usize,
    mut num2: usize,
    ntt_ring_secret_key: &NTTPolynomial<F>,
    basis: Basis<F>,
    half_delta: F,
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
        num1 = num1 >> trailing_zeros;
    }

    while num2 != 0 {
        num2_vec.push(num2 & mask);
        num2 = num2 >> trailing_zeros;
    }

    let len = num1_vec.len().max(num2_vec.len()).max(1);
    num1_vec.resize(len, 0);
    num2_vec.resize(len, 0);

    let vec1 = rlwe_values(
        &num1_vec,
        ntt_ring_secret_key,
        half_delta,
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

/// decrypt
pub fn decrypt<F: Field<Value = u64> + NTTField>(sk: &[F], ciphertext: LWE<F>) -> u64 {
    let a_mul_s = sk
        .iter()
        .zip(ciphertext.a())
        .fold(F::zero(), |acc, (&s, &a)| acc + s * a);
    let outcome = decode(ciphertext.b() - a_mul_s);
    outcome
}

/// Peforms the operation turning a value to its real number
pub fn decode<F: Field<Value = u64> + NTTField>(c: F) -> u64 {
    (c.value() as f64 * FT as f64 / FP as f64).round() as u64 % FT
}

/// Performs the operation of turning a vector to the corresponding RGSW ciphertext.
///
/// # Arguments
///
/// * Input: vector `values`.
/// * Output:corresponding RGSW ciphertext.
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
        // rgsw_turn(&mut rgsw, v, ring_dimension);

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
/// * Output:corresponding RLWE ciphertext.
fn rlwe_values<F, R>(
    values: &[usize],
    ntt_ring_secret_key: &NTTPolynomial<F>,
    half_delta: F,
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
        rlwe.b_mut()[0] += half_delta;
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

/// Performs the RGSW rotation operation.
///
/// # Arguments
///
/// * Input: RGSW ciphertext `ciphertext`.
/// * Input: usize number `num`.
/// * Input: the size of RGSW vector `poly_length`.
/// * Output:RGSW ciphertext `ciphertext*x^(-num)`.
pub fn rgsw_turn<F: NTTField>(ciphertext: &mut RGSW<F>, num: usize, ring_dimension: usize) {
    let start = ring_dimension.checked_sub(num).unwrap();
    for rlwe in ciphertext.c_neg_s_m_mut().iter_mut() {
        let (a, b) = rlwe.a_b_mut_slices();
        a.rotate_left(num);
        b.rotate_left(num);
        for elem in &mut a[start..] {
            *elem = -*elem;
        }
        for elem in &mut b[start..] {
            *elem = -*elem;
        }
    }
    for rlwe in ciphertext.c_m_mut().iter_mut() {
        let (a, b) = rlwe.a_b_mut_slices();
        a.rotate_left(num);
        b.rotate_left(num);
        for elem in &mut a[start..] {
            *elem = -*elem;
        }
        for elem in &mut b[start..] {
            *elem = -*elem;
        }
    }
}

/// Performs the RGSW rotation operation.
///
/// # Arguments
///
/// * Input: RGSW ciphertext `ciphertext`, which encrypts `0`.
/// * Input: usize number `num`.
/// * Input: the size of RGSW vector `ring_dimension`.
/// * Output:RGSW ciphertext `x^(-num)`.
pub fn ntt_rgsw_turn<F: NTTField>(
    ciphertext: &mut NTTRGSW<F>,
    num: usize,
    ring_dimension: usize,
    basis: Basis<F>,
) {
    // X^{-num}
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

/// Complete the bootstrapping operation with LWE Ciphertext *`ciphertext`*, vector *`test_vector`* and BlindRotationKey `key`
pub fn gatebootstrapping<F: Field<Value = u64> + NTTField>(
    ciphertext: LWE<F>,
    mut test_vector: Vec<F>,
    key: &RLWEBlindRotationKey<F>,
) -> LWE<F> {
    let poly_len = test_vector.len();
    let mod_after: u64 = poly_len as u64 * 2;
    let switch = lwe_modulus_switch(ciphertext, mod_after, ModulusSwitchRoundMethod::Round);
    let lwe_modulus = PowOf2Modulus::<u64>::new(mod_after);
    let a = switch.a();
    let b = switch.b();
    let binary_key = match key {
        RLWEBlindRotationKey::Binary(binary_key) => binary_key,
        RLWEBlindRotationKey::Ternary(_) => panic!(),
    };
    let b = b as usize;
    if b <= poly_len {
        test_vector.rotate_right(b);
        for elem in &mut test_vector[..b] {
            *elem = -*elem;
        }
    } else {
        let len = b - poly_len;
        test_vector.rotate_right(len);
        for elem in &mut test_vector[len..] {
            *elem = -*elem;
        }
    }
    let acc = RLWE::new(
        Polynomial::<F>::zero(poly_len),
        Polynomial::<F>::new(test_vector),
    );
    let twice_rlwe_dimension_div_lwe_modulus: usize = 1;
    let temp = binary_key.blind_rotate(
        acc,
        a,
        poly_len,
        twice_rlwe_dimension_div_lwe_modulus,
        lwe_modulus,
    );
    RLWE::extract_lwe(&temp)
}

/// Performs the homomorphic and operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `ca`, with message `a`.
/// * Input: LWE ciphertext `cb`, with message `b`.
/// * Output: LWE ciphertext with message `a & b`.
pub fn homand<F: Field<Value = u64> + NTTField>(
    ca: &LWE<F>,
    cb: &LWE<F>,
    key: &RLWEBlindRotationKey<F>,
    poly_length: usize,
) -> LWE<F> {
    let mut temp = ca.add_component_wise_ref(cb);

    for elem in temp.a_mut().iter_mut() {
        *elem = *elem + *elem + *elem + *elem;
    }
    *temp.b_mut() = temp.b() + temp.b() + temp.b() + temp.b();

    let mut test = vec![F::zero(); poly_length];
    let x = poly_length >> 2;
    let q_div_32 = F::new(F::MODULUS_VALUE >> 5);
    let neg_q_div_32 = F::new(F::MODULUS_VALUE - q_div_32.value());
    test[0..=x].iter_mut().for_each(|a| *a = neg_q_div_32);
    let mut iter = test[x..].iter_mut();
    iter.next();
    iter.for_each(|a| *a = q_div_32);

    let mut r = gatebootstrapping(temp, test, key);
    *r.b_mut() += q_div_32;
    r
}

/// Performs the greater homomorphic comparison "greater" operation of two elements of the vector.
///
/// # Arguments
///
/// * Input: RLWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: the encryption of 1/2 'half_delta'.
/// * Input: the size of RLWE and RGSW vector `poly_length`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2, otherwise 0.
pub fn greater_hcmp<F: NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &NTTRGSW<F>,
    half_delta: F,
    poly_length: usize,
) -> LWE<F> {
    let mul = cipher1.mul_ntt_rgsw(&cipher2);
    let vector = vec![F::neg_one(); poly_length];
    let test_plaintext = Polynomial::<F>::new(vector);
    let trlwe_mul_a = mul.a() * &test_plaintext;
    let trlwe_mul_b = mul.b() * test_plaintext;
    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);
    *res.b_mut() += half_delta;
    res
}

/// Performs the homomorphic comparison "greater" operation of two encoded numbers.
///
/// # Arguments
///
/// * Input: RLWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Input: the encryption of 1 'delta'.
/// * Input: the encryption of 1/2 'half_delta'.
/// * Input: the size of RLWE and RGSW vector `poly_length`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2,otherwise c=0.
pub fn greater_arbhcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[NTTRGSW<F>],
    gatebootstrappingkey: &RLWEBlindRotationKey<F>,
    delta: F,
    half_delta: F,
    poly_length: usize,
) -> LWE<F> {
    let len = cipher1.len();
    assert_eq!(len, cipher2.len());
    assert!(len > 0);
    if len == 1 {
        greater_hcmp(&cipher1[0], &cipher2[0], half_delta, poly_length)
    } else {
        let (cipher1_last, cipher1_others) = cipher1.split_last().unwrap();
        let (cipher2_last, cipher2_others) = cipher2.split_last().unwrap();
        let mut low_part_gt_res = greater_arbhcmp(
            cipher1_others,
            cipher2_others,
            gatebootstrappingkey,
            delta,
            half_delta,
            poly_length,
        );
        for elem in low_part_gt_res.a_mut().iter_mut() {
            *elem = *elem + *elem + *elem + *elem;
        }
        *low_part_gt_res.b_mut() =
            low_part_gt_res.b() + low_part_gt_res.b() + low_part_gt_res.b() + low_part_gt_res.b();
        let eq_res = cipher1_last
            .mul_ntt_rgsw(cipher2_last)
            .extract_lwe_locally();
        let eq_res = eq_res.add_component_wise_ref(&eq_res);
        let mut gt_res = greater_hcmp(cipher1_last, cipher2_last, half_delta, poly_length);
        for elem in gt_res.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *gt_res.b_mut() = gt_res.b() + gt_res.b();
        let new_lwe = eq_res
            .add_component_wise(&low_part_gt_res)
            .add_component_wise(&gt_res);
        let mut test = vec![F::zero(); poly_length];
        let mu = -delta;
        let chunk = poly_length / 8;
        test[chunk * 2..chunk * 3].iter_mut().for_each(|v| *v = mu);
        test[chunk * 5..].iter_mut().for_each(|v| *v = mu);
        test.reverse();
        test.rotate_right(chunk / 2);
        gatebootstrapping(new_lwe, test, gatebootstrappingkey)
    }
}

/// Performs the homomorphic comparison "equality" operation of two elements of the vector.
///
/// # Arguments
///
/// * Input: RLWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=0.
pub fn equality_hcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &NTTRGSW<F>,
) -> LWE<F> {
    let mul = cipher1.mul_ntt_rgsw(&cipher2);
    let mut res = RLWE::extract_lwe(&mul);
    for elem in res.a_mut().iter_mut() {
        *elem = *elem + *elem;
    }
    *res.b_mut() = *res.b_mut() + *res.b_mut();
    res
}

/// Performs the homomorphic comparison "equality" operation of two encoded numbers.
///
/// # Arguments
///
/// * Input: RLWE ciphertext vector `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Input: the size of RLWE and RGSW vector `poly_length`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=0.
pub fn equality_arbhcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[NTTRGSW<F>],
    gatebootstrappingkey: &RLWEBlindRotationKey<F>,
    poly_length: usize,
) -> LWE<F> {
    let len = cipher1.len();
    assert_eq!(len, cipher2.len());
    assert!(len > 0);
    if len == 1 {
        equality_hcmp(&cipher1[0], &cipher2[0])
    } else {
        let (cipher1_last, cipher1_others) = cipher1.split_last().unwrap();
        let (cipher2_last, cipher2_others) = cipher2.split_last().unwrap();
        let low_res = equality_arbhcmp(
            cipher1_others,
            cipher2_others,
            gatebootstrappingkey,
            poly_length,
        );
        let gt_res = equality_hcmp(cipher1_last, cipher2_last);
        let res = homand(&low_res, &gt_res, gatebootstrappingkey, poly_length);
        res
    }
}

/// Performs the greater homomorphic comparison "less" operation of two elements of the vector.
///
/// # Arguments
///
/// * Input: RLWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: the encryption of 1/2 'half_delta'.
/// * Input: the size of RLWE and RGSW vector `poly_length`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_hcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &NTTRGSW<F>,
    half_delta: F,
    poly_length: usize,
) -> LWE<F> {
    let mul = cipher1.mul_ntt_rgsw(&cipher2);
    let mut vector = vec![F::one(); poly_length];
    vector[0] = F::neg_one();
    let test_plaintext = Polynomial::<F>::new(vector).into_ntt_polynomial();
    let trlwe_mul_a = mul.a() * &test_plaintext;
    let trlwe_mul_b = mul.b() * test_plaintext;
    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);
    *res.b_mut() += half_delta;
    res
}

/// Performs the homomorphic comparison "less" operation of two encoded numbers.
///
/// # Arguments
///
/// * Input: RLWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Input: the encryption of 1 'delta'.
/// * Input: the encryption of 1/2 'half_delta'.
/// * Input: the size of RLWE and RGSW vector `poly_length`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_arbhcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[NTTRGSW<F>],
    gatebootstrappingkey: &RLWEBlindRotationKey<F>,
    delta: F,
    half_delta: F,
    poly_length: usize,
) -> LWE<F> {
    let len = cipher1.len();
    assert_eq!(len, cipher2.len());
    assert!(len > 0);
    if len == 1 {
        less_hcmp(&cipher1[0], &cipher2[0], half_delta, poly_length)
    } else {
        let (cipher1_last, cipher1_others) = cipher1.split_last().unwrap();
        let (cipher2_last, cipher2_others) = cipher2.split_last().unwrap();
        let mut low_part_lt_res = less_arbhcmp(
            cipher1_others,
            cipher2_others,
            gatebootstrappingkey,
            delta,
            half_delta,
            poly_length,
        );
        for elem in low_part_lt_res.a_mut().iter_mut() {
            *elem = *elem + *elem + *elem + *elem;
        }
        *low_part_lt_res.b_mut() =
            low_part_lt_res.b() + low_part_lt_res.b() + low_part_lt_res.b() + low_part_lt_res.b();

        let eq_res = cipher1_last
            .mul_ntt_rgsw(cipher2_last)
            .extract_lwe_locally();
        let eq_res = eq_res.add_component_wise_ref(&eq_res);

        let mut lt_res = less_hcmp(cipher1_last, cipher2_last, half_delta, poly_length);
        for elem in lt_res.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *lt_res.b_mut() = lt_res.b() + lt_res.b();
        let new_lwe = eq_res
            .add_component_wise(&low_part_lt_res)
            .add_component_wise(&lt_res);

        let mut test = vec![F::zero(); poly_length];
        let mu = -delta;
        let chunk = poly_length / 8;
        test[chunk * 2..chunk * 3].iter_mut().for_each(|v| *v = mu);
        test[chunk * 5..].iter_mut().for_each(|v| *v = mu);
        test.reverse();
        test.rotate_right(chunk / 2);
        gatebootstrapping(new_lwe, test, gatebootstrappingkey)
    }
}
