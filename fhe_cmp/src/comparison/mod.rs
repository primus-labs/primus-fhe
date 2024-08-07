//!

use algebra::{modulus::PowOf2Modulus, AsFrom, AsInto, Field, NTTField, Polynomial};
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
    let lwe_modulus = PowOf2Modulus::<u64>::new(mod_after);
    let temp = binary_key.blind_rotate(
        acc,
        a,
        poly_len,
        twice_rlwe_dimension_div_lwe_modulus,
        lwe_modulus,
    );
    RLWE::extract_lwe(&temp)
}

/*

/// Performs the homomorphic and operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `ca`, with message `a`.
/// * Input: LWE ciphertext `cb`, with message `b`.
/// * Output: LWE ciphertext with message `a and b`.
pub fn homand<F:Field<Value=u64>+NTTField>(
    ca:LWE<F>,
    cb:LWE<F>,
    key:RLWEBlindRotationKey<F>,
)->LWE<F>{
    let mut temp: Vec<F> = vec![0.into();N+1];
    for i in 0..N+1{
        temp[i] = -ca.a()[i] - cb.a()[i];
    }
    let offset = F::new(U);
    temp[N] = temp[N] + offset;
    let lwe_temp=LWE::new(temp,N.into());
    let num = F::new(3758096384);
    let test= vec![num;N+1];
    let res = gatebootstrapping(lwe_temp,test,key);
    return res;
}


*/

/// Performs the greater homomorphic comparison "greater" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2, otherwise 0.
pub fn greater_hcmp<F: NTTField>(cipher1: &RLWE<F>, cipher2: &RGSW<F>, half_delta: F) -> LWE<F> {
    let poly_len = cipher1.a().coeff_count();
    let mul = cipher1.mul_rgsw(&cipher2);

    let vector = vec![F::neg_one(); poly_len];
    let test_plaintext = Polynomial::<F>::new(vector);

    let trlwe_mul_a = mul.a() * &test_plaintext;
    let trlwe_mul_b = mul.b() * test_plaintext;

    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);

    *res.b_mut() += half_delta;

    return res;
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
    sk: &[F],
) -> LWE<F> {
    let q: f64 = F::MODULUS_VALUE.as_into();
    let decode = |c: F| -> F {
        F::new(F::Value::as_from(
            (AsInto::<f64>::as_into(c.value()) * 16.0f64 / q)
                .round()
                .rem_euclid(16.0),
        ))
    };
    let len = cipher1.len();
    assert_eq!(len, cipher2.len());
    assert!(len > 0);
    if len == 1 {
        greater_hcmp(&cipher1[0], &cipher2[0], half_delta)
    } else {
        let (cipher1_last, cipher1_others) = cipher1.split_last().unwrap();
        let (cipher2_last, cipher2_others) = cipher2.split_last().unwrap();

        let mut low_res = greater_arbhcmp_fixed(
            cipher1_others,
            cipher2_others,
            gatebootstrappingkey,
            delta,
            half_delta,
            sk,
        );
        let dec = low_res.b()
            - low_res
                .a()
                .iter()
                .zip(sk)
                .fold(F::zero(), |acc, (&a, &s)| acc + a * s);
        println!("low_res:{}", decode(dec));
        for elem in low_res.a_mut().iter_mut() {
            *elem = *elem + *elem + *elem + *elem;
        }
        *low_res.b_mut() = low_res.b() + low_res.b() + low_res.b() + low_res.b();

        let mul = cipher1_last.mul_rgsw(cipher2_last);
        let eq_res = RLWE::extract_lwe(&mul);
        let eq_res = eq_res.add_component_wise_ref(&eq_res);

        let dec = eq_res.b()
            - eq_res
                .a()
                .iter()
                .zip(sk)
                .fold(F::zero(), |acc, (&a, &s)| acc + a * s);
        println!("eq_res:{}", decode(dec));

        let mut gt_res = greater_hcmp(cipher1_last, cipher2_last, half_delta);
        let dec = gt_res.b()
            - gt_res
                .a()
                .iter()
                .zip(sk)
                .fold(F::zero(), |acc, (&a, &s)| acc + a * s);
        println!("gt_res:{}", decode(dec));
        //到目前为止，gt_res和eq_res都是正确的;
        for elem in gt_res.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *gt_res.b_mut() = gt_res.b() + gt_res.b();

        //目前没有问题,low,high,equal都是正确的
        let offset = half_delta;
        let mut new_lwe = eq_res
            .add_component_wise(&low_res)
            .add_component_wise(&gt_res);
        *new_lwe.b_mut() += offset;

        let dec = new_lwe.b()
            - new_lwe
                .a()
                .iter()
                .zip(sk)
                .fold(F::zero(), |acc, (&a, &s)| acc + a * s);
        println!("new_lwe:{}", decode(dec));
        //目前为止正确，offset未验证
        let poly_len = cipher1_last.a().coeff_count();
        let mut test = vec![F::zero(); poly_len];
        let chunk = poly_len / 8;
        test[chunk * 2..chunk * 3]
            .iter_mut()
            .for_each(|v| *v = delta);
        test[chunk * 5..].iter_mut().for_each(|v| *v = delta);

        gatebootstrapping(new_lwe, test, gatebootstrappingkey)
    }
}

/*

/// Performs the arbitary-precision homomorphic comparison "greater" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: ciphersize `cipher_size`.
/// * Input: chosen scale `scale_bits`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2,otherwise c=0.
pub fn greater_arbhcmp_arbitary<F:Field<Value=u64>+NTTField>(
    cipher1: &Vec<RLWE<F>>,
    cipher2: &Vec<RGSW<F>>,
    cipher_size:usize,
    scale_bits:usize,
    gatebootstrappingkey:RLWEBlindRotationKey<F>,
)->LWE<F>{
    if cipher_size == 1{
        return greater_hcmp(&cipher1[0],&cipher2[0]);
    }
    else{
        let key_clone = gatebootstrappingkey.clone();
        let low_res= greater_arbhcmp_fixed(cipher1,cipher2,cipher_size-1,gatebootstrappingkey);
        let mul = cipher1[cipher_size-1].mul_rgsw(&cipher2[cipher_size-1]);
        let equal_res = RLWE::extract_lwe(&mul);
        let high_res =  greater_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
        let mut high_plus = vec![F::zero();N+1];
        for i in 0..N+1{
            high_plus[i] = high_res.a()[i] + high_res.a()[i];
        }
        let mut tlwelvl1: Vec<F> = vec![0.into();N+1];
        for i in 0..N+1{
            tlwelvl1[i] = low_res.a()[i] + equal_res.a()[i] + high_plus[i];
        }
        let offset = F::new(U>>1);
        let c =F::new(1<<(scale_bits-1));
        tlwelvl1[N] = tlwelvl1[N] + offset;
        let new_lwe=LWE::new(tlwelvl1,low_res.b());
        let test= vec![c;N+1];
        let mut res = gatebootstrapping(new_lwe,test,key_clone);
        res.a_mut()[N]=res.a_mut()[N]+c;
        return res;
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
    let u = 7156359169 / 8;
    *res.b_mut() = *res.b_mut() + *res.b_mut() - F::new(u);
    res
}

/*
/// Performs the arbitary-precision homomorphic comparison "equality" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=0.
pub fn equality_arbhcmp<F:Field<Value=u64>+NTTField>(
    cipher1: &Vec<RLWE<F>>,
    cipher2: &Vec<RGSW<F>>,
    cipher_size:usize,
    gatebootstrappingkey:RLWEBlindRotationKey<F>,
)->LWE<F>{
    if cipher_size == 1{
        return equality_hcmp(&cipher1[0],&cipher2[0]);
    }
    else{
        let key_clone = gatebootstrappingkey.clone();
        let low_res = equality_arbhcmp(cipher1, cipher2, cipher_size-1,gatebootstrappingkey);
        let high_res = equality_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
        let res = homand(low_res,high_res,key_clone);
        return res;
    }
}


*/

/// Performs the greater homomorphic comparison "less" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_hcmp<F: Field<Value = u64> + NTTField>(cipher1: &RLWE<F>, cipher2: &RGSW<F>) -> LWE<F> {
    let poly_len = cipher1.a().coeff_count();
    let mul = cipher1.mul_rgsw(&cipher2);
    let vector = vec![F::one(); poly_len];
    let test_plaintext = Polynomial::<F>::new(vector);
    let trlwe_mul_a = mul.a() * &test_plaintext;
    let trlwe_mul_b = mul.b() * test_plaintext;
    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    RLWE::extract_lwe(&trlwe_mul)
}

/*

/// Performs the fixed-precision homomorphic comparison "less" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Input: ciphersize `cipher_size`.
/// * Input: BlindRotationKey `gatebootstrappingkey`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_arbhcmp<F:Field<Value=u64>+NTTField>(
    cipher1: &Vec<RLWE<F>>,
    cipher2: &Vec<RGSW<F>>,
    cipher_size:usize,
    gatebootstrappingkey:RLWEBlindRotationKey<F>,
)->LWE<F>{
    if cipher_size == 1{
        return less_hcmp(&cipher1[0],&cipher2[0]);
    }
    else{
        let key_clone = gatebootstrappingkey.clone();
        let low_res= less_arbhcmp(cipher1,cipher2,cipher_size-1,gatebootstrappingkey);
        let mul = cipher1[cipher_size-1].mul_rgsw(&cipher2[cipher_size-1]);
        let equal_res = RLWE::extract_lwe(&mul);
        let high_res =  less_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
        let mut high_plus = vec![F::zero();N+1];
        for i in 0..N+1{
            high_plus[i] = high_res.a()[i] + high_res.a()[i];
        }
        let mut tlwelvl1: Vec<F> = vec![0.into();N+1];
        for i in 0..N+1{
            tlwelvl1[i] = low_res.a()[i] + equal_res.a()[i] + high_plus[i];
        }
        let offset = F::new(U>>1);
        tlwelvl1[N] = tlwelvl1[N] + offset;
        let new_lwe=LWE::new(tlwelvl1,low_res.b());
        let num = F::new(3758096384);
        let test= vec![num;N+1];
        let res = gatebootstrapping(new_lwe,test,key_clone);
        return res;
    }
}



*/
