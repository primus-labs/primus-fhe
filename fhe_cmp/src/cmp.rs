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
pub fn rlwe_turn<F: Field<Value = u64> + NTTField>(mut ciphertext: RLWE<F>, num: usize) -> RLWE<F> {
    let (ciphertext_a, ciphertext_b) = ciphertext.a_b_mut();
    let a_mut = ciphertext_a.data_mut();
    let b_mut = ciphertext_b.data_mut();
    a_mut.rotate_right(num);
    b_mut.rotate_right(num);
    for elem in a_mut.iter_mut().take(num) {
        *elem = -*elem;
    }
    for elem in b_mut.iter_mut().take(num) {
        *elem = -*elem;
    }
    return ciphertext;
}

/// Performs the rgsw rotation operation.
///
/// # Arguments
///
/// * Input: RGSW ciphertext `ciphertext`.
/// * Input: usize number `num`.
/// * Output:RGSW ciphertext `ciphertext*x^(-num)`.
pub fn rgsw_turn<F: Field<Value = u64> + NTTField>(mut ciphertext: RGSW<F>, num: usize) -> RGSW<F> {
    for elem_out in ciphertext.c_neg_s_m_mut().iter_mut() {
        let (a, b) = elem_out.a_b_mut_slices();
        a.rotate_left(num);
        b.rotate_left(num);
        for elem in a.iter_mut().rev().take(num) {
            *elem = -*elem;
        }
        for elem in b.iter_mut().rev().take(num) {
            *elem = -*elem;
        }
    }
    for elem_out in ciphertext.c_m_mut().iter_mut() {
        let (a, b) = elem_out.a_b_mut_slices();
        a.rotate_left(num);
        b.rotate_left(num);
        for elem in a.iter_mut().rev().take(num) {
            *elem = -*elem;
        }
        for elem in b.iter_mut().rev().take(num) {
            *elem = -*elem;
        }
    }
    return ciphertext;
}

/// Complete the bootstrapping operation with LWE Ciphertext *`ciphertext`*, vector *`test_vector`* and BlindRotationKey `key`
pub fn gatebootstrapping<F: Field<Value = u64> + NTTField>(
    ciphertext: LWE<F>,
    mut test_vector: Vec<F>,
    key: RLWEBlindRotationKey<F>,
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
    if ciphertext_change_b < 1024 {
        test_vector.rotate_right(ciphertext_change_b);
        for elem in test_vector.iter_mut().take(ciphertext_change_b) {
            *elem = -*elem;
        }
    } else if ciphertext_change_b == 1024 {
        for elem in test_vector.iter_mut() {
            *elem = -*elem;
        }
    } else {
        test_vector.rotate_right(ciphertext_change_b - 1024);
        for elem in test_vector
            .iter_mut()
            .rev()
            .take(2048 - ciphertext_change_b)
        {
            *elem = -*elem;
        }
    }
    let vector1 = vec![F::new(0); N];
    let text1 = Polynomial::<F>::new(vector1);
    let text2 = Polynomial::<F>::new(test_vector);
    let acc = RLWE::new(text1, text2);
    let modulus: usize = 1;
    let m = 2048;
    let l_modulus = PowOf2Modulus::<u64>::new(m);
    let temp = binary_key.blind_rotate(acc, ciphertext_change_a, N, modulus, l_modulus);
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
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2, otherwise -1.
pub fn greater_hcmp<F: Field<Value = u64> + NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
) -> LWE<F> {
    let mul = cipher1.mul_rgsw(&cipher2);
    let vector = vec![F::one(); N];
    let test_plaintext = Polynomial::<F>::new(vector);
    let trlwe_mul_a = mul.a() * (&test_plaintext);
    let trlwe_mul_b = mul.b() * (&test_plaintext);
    let trlwe_mul = RLWE::new(trlwe_mul_a, trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);
    for elem in res.a_mut().iter_mut() {
        *elem = -*elem;
    }
    *res.b_mut() = -*res.b_mut();
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
    gatebootstrappingkey: RLWEBlindRotationKey<F>,
) -> LWE<F> {
    if cipher_size == 1 {
        return greater_hcmp(&cipher1[0], &cipher2[0]);
    } else {
        let key_clone = gatebootstrappingkey.clone();
        let low_res =
            greater_arbhcmp_fixed(cipher1, cipher2, cipher_size - 1, gatebootstrappingkey);
        let mul = cipher1[cipher_size - 1].mul_rgsw(&cipher2[cipher_size - 1]);
        let equal_res = RLWE::extract_lwe(&mul);
        let mut high_res = greater_hcmp(&cipher1[cipher_size - 1], &cipher2[cipher_size - 1]);
        //到目前为止，high_res和equal_res都是正确的;
        for elem in high_res.a_mut().iter_mut() {
            *elem = *elem + *elem;
        }
        *high_res.b_mut() = *high_res.b_mut() + *high_res.b_mut();
        //目前没有问题,low,high,equal都是正确的
        let u = 81720453121 / 8;
        let offset = F::new(u / 2);
        let mut tlwelvl1_a: Vec<F> = vec![0.into(); N];
        for i in 0..N {
            tlwelvl1_a[i] = low_res.a()[i] + equal_res.a()[i] + high_res.a()[i];
        }
        let mut tlwelvl1_b = low_res.b() + equal_res.b() + high_res.b();
        tlwelvl1_b = tlwelvl1_b + offset;
        let new_lwe = LWE::new(tlwelvl1_a, tlwelvl1_b);
        //目前为止正确，offset未验证
        let test = vec![F::new(u); N];
        let res = gatebootstrapping(new_lwe, test, key_clone);
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
