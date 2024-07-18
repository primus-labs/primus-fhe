//! This is the implementation of homomorphic comparison.
use algebra::{Field, NTTField, NTTPolynomial, Polynomial,modulus::PowOf2Modulus};
use lattice::{RLWE, LWE, RGSW};
use fhe_core::{RLWEBlindRotationKey,lwe_modulus_switch};

const N:usize= 1024;
const U:u32= 1<<29;
pub struct SK<F:Field<Value=u32>+NTTField>{
    key: Vec<F>
}

impl<F:Field<Value=u32>+NTTField> SK<F> { 
    pub fn gatebootstrapping(
        ciphertext: LWE<F>,
        key:RLWEBlindRotationKey<F>,
    )->LWE<F>{
        let switch = lwe_modulus_switch(ciphertext,2048);
        let ciphertext_change=switch.a();
        let binary_key=match key {
            RLWEBlindRotationKey::Binary(binary_key)=> binary_key,
            RLWEBlindRotationKey::Ternary(_)=>panic!(),
        };
        //-(1<<29)=3758096384
        let num1 = F::new(3758096384); //lvl1
        let vector1= vec![num1;N];
        let vector2= vec![F::ZERO;N];
        let text1 = Polynomial::<F>::new(vector1);
        let text2 = Polynomial::<F>::new(vector2);
        let acc=RLWE::new(text1,text2);
        let modulus:usize = 1;
        let m = 2048;
        let ls = PowOf2Modulus::<u32>::new(m);
        let temp = binary_key.blind_rotate(
            acc,
            ciphertext_change,
            N,
            modulus,
            ls,
        );
        let temp_extract = RLWE::extract_lwe(&temp);
        return temp_extract;
    }


    pub fn homand(
        ca:LWE<F>,
        cb:LWE<F>,
        key:RLWEBlindRotationKey<F>,
    )->LWE<F>{
        let mut temp: Vec<F> = vec![0.into();N];
        for i in 0..N+1{
            temp[i] = -ca.a()[i] - cb.a()[i];
        }
        let offset = F::new(1<<29);
        temp[N] = temp[N] + offset;
        let lwe_temp=LWE::new(temp,N.into());
        let res = Self::gatebootstrapping(lwe_temp,key);
        return res;
    }

    pub fn greater_hcmp(
        cipher1: &RLWE<F>,
        cipher2: &RGSW<F>,
    )->LWE<F>{
        let mul = cipher1.mul_small_rgsw(&cipher2);
        let ts= vec![F::ONE;N];
        let test_plaintext = NTTPolynomial::<F>::new(ts);
        let x = (RLWE::a(&mul))*(&test_plaintext);
        let y = (RLWE::b(&mul))*(&test_plaintext);
        let trlwe_mul = RLWE::new(x,y);
        let mut res = RLWE::extract_lwe(&trlwe_mul);
        for elem in res.a_mut().iter_mut(){
            *elem = -*elem;
        }
        return res;
    }

    pub fn greater_arbhcmp(
        cipher1: &Vec<RLWE<F>>,
        cipher2: &Vec<RGSW<F>>,
        cipher_size:usize,
        gatebootstrappingkey:RLWEBlindRotationKey<F>,
    )->LWE<F>{
        if cipher_size == 1{
            return Self::greater_hcmp(&cipher1[0],&cipher2[0]);
        }
        else{
            let key_clone = gatebootstrappingkey.clone();
            let low_res= Self::greater_arbhcmp(cipher1,cipher2,cipher_size-1,gatebootstrappingkey);
            let mul = cipher1[cipher_size-1].mul_small_rgsw(&cipher2[cipher_size-1]);
            let equal_res = RLWE::extract_lwe(&mul);
            let high_res =  Self::greater_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
            let mut high_plus = vec![F::ZERO;N];
            for i in 0..N+1{
                high_plus[i] = high_res.a()[i] + high_res.a()[i];
            }
            let mut tlwelvl1: Vec<F> = vec![0.into();N];
            for i in 0..N+1{
                tlwelvl1[i] = low_res.a()[i] + equal_res.a()[i] + high_plus[i];
            }
            let offset = F::new(1<< 10);
            tlwelvl1[N] = tlwelvl1[N] + offset;
            let new_lwe=LWE::new(tlwelvl1,low_res.b());
            let res = Self::gatebootstrapping(new_lwe,key_clone);
            return res;
        }
    }

    pub fn equality_hcmp(
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


    pub fn equality_arbhcmp(
        cipher1: &Vec<RLWE<F>>,
        cipher2: &Vec<RGSW<F>>,
        cipher_size:usize,
        gatebootstrappingkey:RLWEBlindRotationKey<F>,
    )->LWE<F>{
        if cipher_size == 1{
            return Self::equality_hcmp(&cipher1[0],&cipher2[0]);
        }
        else{
            let key_clone = gatebootstrappingkey.clone();
            let low_res = Self::equality_arbhcmp(cipher1, cipher2, cipher_size-1,gatebootstrappingkey);
            let high_res = Self::equality_hcmp(&cipher1[cipher_size-1],&cipher2[cipher_size-1]);
            let res = Self::homand(low_res,high_res,key_clone);
            return res;
        }

    }



    pub fn less_hcmp(
        cipher1: &RLWE<F>,
        cipher2: &RGSW<F>,
    )->LWE<F>{
        let mul = cipher1.mul_small_rgsw(&cipher2);
        let n = 1 << 10;
        let ts= vec![F::ONE;n];
        let mut test_plaintext = NTTPolynomial::<F>::new(ts);
        test_plaintext[0] = 7.into(); 
        let x = (RLWE::a(&mul))*(&test_plaintext);
        let y = (RLWE::b(&mul))*(&test_plaintext);
        let trlwe_mul = RLWE::new(x,y);
        let res = RLWE::extract_lwe(&trlwe_mul);
        return res;
    }
}
