//!

use algebra::{modulus::PowOf2Modulus, Field, NTTField, Polynomial};
use fhe_core::{lwe_modulus_switch, ModulusSwitchRoundMethod, RLWEBlindRotationKey};
use lattice::{LWE, RGSW, RLWE};

// N:dimension
const N: usize = 1024;

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
    for elem in &mut a[0..num] {
        *elem = -*elem;
    }
    for elem in &mut b[0..num] {
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
pub fn rgsw_turn<F: NTTField>(ciphertext: &mut RGSW<F>, num: usize) {
    for rlwe in ciphertext.c_neg_s_m_mut().iter_mut() {
        let (a, b) = rlwe.a_b_mut_slices();
        let start = a.len() - num;
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
        let start = a.len() - num;
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
    let mod_after: u64 = 2048;
    let switch = lwe_modulus_switch(ciphertext, mod_after, ModulusSwitchRoundMethod::Round);
    let ciphertext_change_a = switch.a();
    let ciphertext_change_b = switch.b();
    let binary_key = match key {
        RLWEBlindRotationKey::Binary(binary_key) => binary_key,
        RLWEBlindRotationKey::Ternary(_) => panic!(),
    };
    let ciphertext_change_b = ciphertext_change_b as usize;
    if ciphertext_change_b <= 1024 {
        test_vector.rotate_right(ciphertext_change_b);
        for elem in &mut test_vector[..ciphertext_change_b] {
            *elem = -*elem;
        }
    } else {
        let len = ciphertext_change_b - 1024;
        test_vector.rotate_right(len);
        for elem in &mut test_vector[len..] {
            *elem = -*elem;
        }
    }

    let text1 = Polynomial::<F>::zero(N);
    let text2 = Polynomial::<F>::new(test_vector);
    let acc = RLWE::new(text1, text2);
    let twice_rlwe_dimension_div_lwe_modulus: usize = 1;
    let m = 2048;
    let lwe_modulus = PowOf2Modulus::<u64>::new(m);
    let temp = binary_key.blind_rotate(
        acc,
        ciphertext_change_a,
        N,
        twice_rlwe_dimension_div_lwe_modulus,
        lwe_modulus,
    );
    let temp_extract = RLWE::extract_lwe(&temp);
    return temp_extract;
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
    let mul = cipher1.mul_rgsw(&cipher2);

    let vector = vec![F::neg_one(); N];
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
    cipher1: &Vec<RLWE<F>>,
    cipher2: &Vec<RGSW<F>>,
    cipher_size: usize,
    gatebootstrappingkey: &RLWEBlindRotationKey<F>,
    delta: F,
    half_delta: F,
) -> LWE<F> {
    if cipher_size == 1 {
        return greater_hcmp(&cipher1[0], &cipher2[0], half_delta);
    } else {
        let mut low_res = greater_arbhcmp_fixed(
            cipher1,
            cipher2,
            cipher_size - 1,
            gatebootstrappingkey,
            delta,
            half_delta,
        );
        for elem in low_res.a_mut().iter_mut() {
            *elem = *elem + *elem + *elem + *elem;
        }
        *low_res.b_mut() = low_res.b() + low_res.b() + low_res.b() + low_res.b();

        let mul = cipher1[cipher_size - 1].mul_rgsw(&cipher2[cipher_size - 1]);
        let mut eq_res = RLWE::extract_lwe(&mul);
        *eq_res.b_mut() += half_delta;

        let mut gt_res = greater_hcmp(
            &cipher1[cipher_size - 1],
            &cipher2[cipher_size - 1],
            half_delta,
        );
        //到目前为止，gt_res和eq_res都是正确的;
        for elem in gt_res.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *gt_res.b_mut() = gt_res.b() + gt_res.b();

        //目前没有问题,low,high,equal都是正确的
        let offset = half_delta;
        let mut tlwelvl1_a: Vec<F> = vec![0.into(); eq_res.a().len()];
        for i in 0..N {
            tlwelvl1_a[i] = eq_res.a()[i] + low_res.a()[i] + gt_res.a()[i];
        }
        let mut tlwelvl1_b = eq_res.b() + low_res.b() + gt_res.b();
        tlwelvl1_b = tlwelvl1_b + offset;
        let new_lwe = LWE::new(tlwelvl1_a, tlwelvl1_b);
        //目前为止正确，offset未验证
        let mut test = vec![F::zero(); N];
        let chunk = N / 8;
        test[chunk * 2..chunk * 3]
            .iter_mut()
            .for_each(|v| *v = delta);
        test[chunk * 5..].iter_mut().for_each(|v| *v = delta);

        let res = gatebootstrapping(new_lwe, test, gatebootstrappingkey);
        return res;
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
    return res;
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
    let mul = cipher1.mul_rgsw(&cipher2);
    let vector = vec![F::one(); N];
    let test_plaintext = Polynomial::<F>::new(vector);
    let trlwe_mul_a = mul.a() * (&test_plaintext);
    let trlwe_mul_b = mul.b() * (&test_plaintext);
    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let res = RLWE::extract_lwe(&trlwe_mul);
    return res;
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
