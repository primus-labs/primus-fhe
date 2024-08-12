//!

use algebra::{modulus::PowOf2Modulus, Field, NTTField, Polynomial};
use fhe_core::{lwe_modulus_switch, ModulusSwitchRoundMethod, RLWEBlindRotationKey};
use lattice::{LWE, RGSW, RLWE};

/// Performs the rlwe rotation operation.
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

/// Performs the rgsw rotation operation.
///
/// # Arguments
///
/// * Input: RGSW ciphertext `ciphertext`.
/// * Input: usize number `num`.
/// * Output:RGSW ciphertext `ciphertext*x^(-num)`.
pub fn rgsw_turn<F: NTTField>(ciphertext: &mut RGSW<F>, num: usize, poly_length: usize) {
    let start = poly_length.checked_sub(num).unwrap();
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
/// * Output: LWE ciphertext with message `a and b`.
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

/// Performs the greater homomorphic comparison "greater" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2, otherwise 0.
pub fn greater_hcmp<F: NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
    half_delta: F,
    poly_length: usize,
) -> LWE<F> {
    let mul = cipher1.mul_rgsw(&cipher2);

    let vector = vec![F::neg_one(); poly_length];
    let test_plaintext = Polynomial::<F>::new(vector);

    let trlwe_mul_a = mul.a() * &test_plaintext;
    let trlwe_mul_b = mul.b() * test_plaintext;

    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);

    *res.b_mut() += half_delta;

    res
}

/// Performs the fixed-precision homomorphic comparison "greater" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: ciphersize `cipher_size`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2,otherwise c=0.
pub fn greater_arbhcmp_fixed<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[RGSW<F>],
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

        let mut low_part_gt_res = greater_arbhcmp_fixed(
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

        let eq_res = cipher1_last.mul_rgsw(cipher2_last).extract_lwe_locally();
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

/*
pub fn greater_arbhcmp_arbitary<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[RGSW<F>],
    gatebootstrappingkey: &RLWEBlindRotationKey<F>,
    scalebits: F,
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

        let mut low_part_gt_res = greater_arbhcmp_fixed(
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

        let eq_res = cipher1_last.mul_rgsw(cipher2_last).extract_lwe_locally();
        let eq_res = eq_res.add_component_wise_ref(&eq_res);

        let mut gt_res = greater_hcmp(cipher1_last, cipher2_last, half_delta, poly_length);

        for elem in gt_res.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *gt_res.b_mut() = gt_res.b() + gt_res.b();


        let mut new_lwe = eq_res
            .add_component_wise(&low_part_gt_res)
            .add_component_wise(&gt_res);


        let mut test = vec![F::zero(); poly_length];
        let mu = -delta;
        let chunk = poly_length / 8;
        let c = 1<<(scalebits.value()-1);
        test[chunk * 2..chunk * 3].iter_mut().for_each(|v| *v = mu);
        test[chunk * 5..].iter_mut().for_each(|v| *v = mu);
        test.reverse();
        test.rotate_right(chunk / 2);
        test.rotate_right(c);

        gatebootstrapping(new_lwe, test, gatebootstrappingkey)
    }
}
*/

/// Performs the homomorphic comparison "equality" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=-1.
pub fn equality_hcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
) -> LWE<F> {
    let mul = cipher1.mul_rgsw(&cipher2);
    let mut res = RLWE::extract_lwe(&mul);
    for elem in res.a_mut().iter_mut() {
        *elem = *elem + *elem;
    }
    *res.b_mut() = *res.b_mut() + *res.b_mut();
    res
}

/// Performs the arbitary-precision homomorphic comparison "equality" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=0.
pub fn equality_arbhcmp_fixed<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[RGSW<F>],
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
        let low_res = equality_arbhcmp_fixed(
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

/// Performs the greater homomorphic comparison "less" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_hcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
    half_delta: F,
    poly_length: usize,
) -> LWE<F> {
    let mul = cipher1.mul_rgsw(&cipher2);

    let mut vector = vec![F::one(); poly_length];
    vector[0] = F::neg_one();
    let test_plaintext = Polynomial::<F>::new(vector);

    let trlwe_mul_a = mul.a() * &test_plaintext;
    let trlwe_mul_b = mul.b() * test_plaintext;

    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);

    *res.b_mut() += half_delta;

    res
}

/// Performs the fixed-precision homomorphic comparison "less" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: ciphersize `cipher_size`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_arbhcmp_fixed<F: Field<Value = u64> + NTTField>(
    cipher1: &[RLWE<F>],
    cipher2: &[RGSW<F>],
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

        let mut low_part_gt_res = less_arbhcmp_fixed(
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

        let eq_res = cipher1_last.mul_rgsw(cipher2_last).extract_lwe_locally();
        let eq_res = eq_res.add_component_wise_ref(&eq_res);

        let mut gt_res = less_hcmp(cipher1_last, cipher2_last, half_delta, poly_length);

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
