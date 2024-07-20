//! This is the implementation of homomorphic comparison.
use algebra::{Field, NTTField, NTTPolynomial, Polynomial,modulus::PowOf2Modulus};
use lattice::{RLWE, LWE, RGSW};
use fhe_core::{RLWEBlindRotationKey,lwe_modulus_switch};

// N:dimension
const N:usize= 1024;
const U:u32= 1<<29;

/// Complete the bootstrapping operation with LWE Ciphertext *`ciphertext`*, vector *`test_vector`* and BlindRotationKey `key`
pub fn gatebootstrapping<F:Field<Value=u32>+NTTField>(
    ciphertext: LWE<F>,
    test_vector:Vec<F>,
    key:RLWEBlindRotationKey<F>,
)->LWE<F>{
    let switch = lwe_modulus_switch(ciphertext,2048);
    let ciphertext_change=switch.a();
    let binary_key=match key {
        RLWEBlindRotationKey::Binary(binary_key)=> binary_key,
        RLWEBlindRotationKey::Ternary(_)=>panic!(),
    };
    let vector2= vec![F::ZERO;N+1];
    let text1 = Polynomial::<F>::new(test_vector);
    let text2 = Polynomial::<F>::new(vector2);
    let acc=RLWE::new(text1,text2);
    let modulus:usize = 1;
    let m = 2048;
    let lwe_modulus = PowOf2Modulus::<u32>::new(m);
    let temp = binary_key.blind_rotate(
        acc,
        ciphertext_change,
        N,
        modulus,
        lwe_modulus,
    );
    let temp_extract = RLWE::extract_lwe(&temp);
    return temp_extract;
}


/// Performs the homomorphic and operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `ca`, with message `a`.
/// * Input: LWE ciphertext `cb`, with message `b`.
/// * Output: LWE ciphertext with message `a and b`.
pub fn homand<F:Field<Value=u32>+NTTField>(
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
    //使用targetp,u是lvl1的
    let res = gatebootstrapping(lwe_temp,test,key);
    return res;
}


/// Performs the greater homomorphic comparison "greater" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1>cipher2,otherwise c=0.
pub fn greater_hcmp<F:Field<Value=u32>+NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
)->LWE<F>{
    let mul = cipher1.mul_small_rgsw(&cipher2);
    let mut test_plaintext= vec![F::ONE;N+1];
    test_plaintext[N] = F::new(0);
    let test_plaintext = NTTPolynomial::<F>::new(test_plaintext);
    let trlwe_mul_a = (RLWE::a(&mul))*(&test_plaintext);
    let trlwe_mul_b = (RLWE::b(&mul))*(&test_plaintext);
    let trlwe_mul = RLWE::new(trlwe_mul_a,trlwe_mul_b);
    let mut res = RLWE::extract_lwe(&trlwe_mul);
    for elem in res.a_mut().iter_mut(){
        *elem = -*elem;
    }
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
pub fn greater_arbhcmp_fixed<F:Field<Value=u32>+NTTField>(
    cipher1: &Vec<RLWE<F>>,
    cipher2: &Vec<RGSW<F>>,
    cipher_size:usize,
    gatebootstrappingkey:RLWEBlindRotationKey<F>,
)->LWE<F>{
    if cipher_size == 1{
        return greater_hcmp(&cipher1[0],&cipher2[0]);
    }
    else{
        let key_clone = gatebootstrappingkey.clone();
        let low_res= greater_arbhcmp_fixed(cipher1,cipher2,cipher_size-1,gatebootstrappingkey);
        let mul = cipher1[cipher_size-1].mul_small_rgsw(&cipher2[cipher_size-1]);
        let equal_res = RLWE::extract_lwe(&mul);
        let high_res =  greater_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
        let mut high_plus = vec![F::ZERO;N+1];
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
pub fn greater_arbhcmp_arbitary<F:Field<Value=u32>+NTTField>(
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
        let mul = cipher1[cipher_size-1].mul_small_rgsw(&cipher2[cipher_size-1]);
        let equal_res = RLWE::extract_lwe(&mul);
        let high_res =  greater_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
        let mut high_plus = vec![F::ZERO;N+1];
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


/// Performs the homomorphic comparison "equality" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=0.
pub fn equality_hcmp<F:Field<Value=u32>+NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
)->LWE<F>{
    let mul = cipher1.mul_small_rgsw(&cipher2);
    let mut res = RLWE::extract_lwe(&mul);
    for elem in res.a_mut().iter_mut(){
        *elem = *elem + *elem;
    }
    res.a_mut()[N]=res.a()[N]-F::new(U);
    return res;
}


/// Performs the arbitary-precision homomorphic comparison "equality" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1=cipher2,otherwise c=0.
pub fn equality_arbhcmp<F:Field<Value=u32>+NTTField>(
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


/// Performs the greater homomorphic comparison "less" operation.
///
/// # Arguments
///
/// * Input: LWE ciphertext `cipher1`, with message `a`.
/// * Input: RGSW ciphertext `cipher2`, with message `b`.
/// * Output: LWE ciphertext output=LWE(c) where c=1 if cipher1<cipher2,otherwise c=0.
pub fn less_hcmp<F:Field<Value=u32>+NTTField>(
    cipher1: &RLWE<F>,
    cipher2: &RGSW<F>,
)->LWE<F>{
    let mul = cipher1.mul_small_rgsw(&cipher2);
    let ts= vec![F::ONE;N+1];
    let mut test_plaintext = NTTPolynomial::<F>::new(ts);
    test_plaintext[0] = F::new(7); 
    test_plaintext[N] = F::new(0); 
    let trlwe_mul_a = (RLWE::a(&mul))*(&test_plaintext);
    let trlwe_mul_b = (RLWE::b(&mul))*(&test_plaintext);
    let trlwe_mul = RLWE::new(trlwe_mul_a,trlwe_mul_b);
    let res = RLWE::extract_lwe(&trlwe_mul);
    return res;
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
pub fn less_arbhcmp<F:Field<Value=u32>+NTTField>(
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
        let mul = cipher1[cipher_size-1].mul_small_rgsw(&cipher2[cipher_size-1]);
        let equal_res = RLWE::extract_lwe(&mul);
        let high_res =  less_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
        let mut high_plus = vec![F::ZERO;N+1];
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
