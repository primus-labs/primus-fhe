use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    DecomposableField, Field, NTTPolynomial, Polynomial,
};
use fhe_cmp::comparison;
use fhe_core::{
    BlindRotationType, ConstParameters, ModulusSwitchRoundMethod, Parameters, RLWEBlindRotationKey,
    RingSecretKeyType, SecretKeyPack, SecretKeyType, StepsAfterBR,
};
use lattice::{NTTRLWE, RGSW, RLWE};
use num_traits::Zero;
use rand::prelude::*;

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct FF(u64);

pub type RingSecretKey<FF> = Polynomial<FF>;
pub type NTTRingSecretKey<FF> = NTTPolynomial<FF>;

type Inner = u64; // inner type

const FP: Inner = FF::MODULUS_VALUE; // ciphertext space
const FT: Inner = 16; // message space
const DEELTA: FF = FF((FP as f64 / FT as f64) as Inner);
const HALF_DEELTA: FF = FF((FP as f64 / (FT as f64 * 2.0)) as Inner);

// #[inline]
// fn encode(m: Inner) -> FF {
//     FF::new((m as f64 * FP as f64 / FT as f64).round() as Inner)
// }

#[inline]
fn half_encode(m: Inner) -> FF {
    FF::new((m as f64 * FP as f64 / (FT as f64 * 2.0)).round() as Inner)
}

#[inline]
fn decode(c: FF) -> Inner {
    (c.value() as f64 * FT as f64 / FP as f64).round() as Inner % FT
}

fn main() {
    let mut rng = thread_rng();
    let param = Parameters::<u64, FF>::new(ConstParameters {
        lwe_dimension: 1024,
        lwe_modulus: 2048,
        t: 16,
        lwe_noise_std_dev: 3.20,
        secret_key_type: SecretKeyType::Binary,
        blind_rotation_type: BlindRotationType::RLWE,
        ring_dimension: 1024,
        ring_modulus: 132120577,
        ring_noise_std_dev: 0.1,
        ring_secret_key_type: RingSecretKeyType::Binary,
        blind_rotation_basis_bits: 1,
        steps_after_blind_rotation: StepsAfterBR::Ms,
        key_switching_basis_bits: 1,
        key_switching_std_dev: 3.20 * 2.175,
        modulus_switcing_round_method: ModulusSwitchRoundMethod::Round,
    })
    .unwrap();

    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let poly_length = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let lwe_sk = sk.lwe_secret_key();

    let value = 1;
    let ntt_num1 = NTTRLWE::generate_random_value_sample(
        sk.ntt_ring_secret_key(),
        half_encode(value),
        sampler,
        &mut rng,
    );
    let mut num1 = RLWE::from(ntt_num1);

    let mut num2 =
        RGSW::generate_random_one_sample(&mut rng, basis, sampler, sk.ntt_ring_secret_key());

    comparison::rlwe_turn(&mut num1, 0);
    comparison::rgsw_turn(&mut num2, 5, poly_length);

    let rotationkey = RLWEBlindRotationKey::generate(&sk, sampler, &mut rng);
    let vec1 = vec![num1.clone(), num1];
    let vec2 = vec![num2.clone(), num2];
    let out1 = comparison::greater_arbhcmp_fixed(
        &vec1,
        &vec2,
        &rotationkey,
        DEELTA,
        HALF_DEELTA,
        lwe_sk,
        rlwe_sk,
    );

    let a_mul_s = rlwe_sk
        .iter()
        .zip(out1.a())
        .fold(FF::zero(), |acc, (&s_i, &a_i)| acc + s_i * a_i);
    let decoded_value1 = decode(out1.b() - a_mul_s);
    //low_res恒为1，无误 equal_res为0 high_res 有问题
    println!("{}", decoded_value1);
    /*
    let out_a=out.a();
    let mut num = FF::new(0);
    for i in 0..1024{
        num = num +code[i]*out_a[i];
    }
    let decoded_value = decode(out.b()-num);
    println!("{}",decoded_value);
    */

    /*
        let in1=comparison::rlwe_turn(num1,1);
        let in2=comparison::rgsw_turn(num2,0);
        let out1 = comparison::greater_hcmp(&in1,&in2);
        let out2 = comparison::equality_hcmp(&in1, &in2);
        let out3 = comparison::less_hcmp(&in1, &in2);



        let out1_a=out1.a();
        let out2_a=out2.a();
        let out3_a=out3.a();


        let mut num1 = FF::new(0);
        let mut num2 = FF::new(0);
        let mut num3 = FF::new(0);


        for i in 0..1024{
            num1 = num1 +code[i]*out1_a[i];
        }
        for i in 0..1024{
            num2 = num2 +code[i]*out2_a[i];
        }
        for i in 0..1024{
            num3 = num3 +code[i]*out3_a[i];
        }


        let decoded_value1 = decode(out1.b()-num1);
        let decoded_value2 = decode(out2.b()-num2);
        let decoded_value3 = decode(out3.b()-num3);


        println!("{}",decoded_value1);
        println!("{}",decoded_value2);
        println!("{}",decoded_value3);
    */
}

/*
fn test_all(){
    //init
    let mut rng = thread_rng();
    let param=Parameters::<u16, FF>::new(ConstParameters {
        lwe_dimension: 1024,
        lwe_modulus: 1024,
        t: 4,
        lwe_noise_std_dev: 3.20,
        secret_key_type: SecretKeyType::Binary,
        blind_rotation_type: BlindRotationType::RLWE,
        ring_dimension: 1024,
        ring_modulus: FF::MODULUS_VALUE,
        ring_noise_std_dev: 3.20 * 2.175,
        ring_secret_key_type: RingSecretKeyType::Binary,
        blind_rotation_basis_bits: 3,
        steps_after_blind_rotation: StepsAfterBR::Ms,
        key_switching_basis_bits: 1,
        key_switching_std_dev: 3.20 * 2.175,
        modulus_switcing_round_method: ModulusSwitchRoundMethod::Round,
    })
    .unwrap();
    let sk =SecretKeyPack::new(param);
    let value = 1;
    let basis = <Basis<FF>>::new(3);
    let code = sk.ring_secret_key().as_slice();
    let sampler = param.ring_noise_distribution();
    let ntt_num1=NTTRLWE::generate_random_value_sample(
        sk.ntt_ring_secret_key(),
        encode(value),
        sampler,
        &mut rng
    );
    let num2 = RGSW::generate_random_one_sample(
        &mut rng,
        basis,
        sampler,
        sk.ntt_ring_secret_key()
    );
    let num1=RLWE::from(ntt_num1);
    let num0_0=num1.clone();
    let mut num0_2=num2.clone();
    let num1_1=num1.clone();
    let num2_1=num2.clone();
    let num1_2=num1.clone();
    let num2_2=num2.clone();
    //now, we have 2 ciphertext, num1 and num2 representing 1 in rlwe and rgsw
    //test rlwe_turn
    //num before rotate
    //num after rotate


    let in1_0=comparison::rlwe_turn(num1,2);
    let mut vec_0=vec![FF::new(0);1024];
    vec_0[2]=FF::new(1);
    let pol_0=Polynomial::new(vec_0);
    let mul_0=num0_0.a() * (&pol_0);
    let mul_1=num0_0.b() * (&pol_0);
    assert_eq!(in1_0.a(),&mul_0);
    assert_eq!(in1_0.b(),&mul_1);


    //test rgsw_turn
    let in2_0=comparison::rgsw_turn(num2,1);
    let mut vec_1=vec![FF::new(0);1024];
    vec_1[1]=FF::new(1);
    let pol_1=Polynomial::new(vec_1);
    for elem_out in num0_2.c_neg_s_m_mut().iter_mut() {
        let a = elem_out.a_mut();
        *a= (*a).clone()*(&pol_1);
        let b =elem_out.b_mut();
        *b=(*b).clone()*(&pol_1);
    }
    for elem_out in num0_2.c_m_mut().iter_mut() {
        let a = elem_out.a_mut();
        *a= (*a).clone()*(&pol_1);
        let b =elem_out.b_mut();
        *b=(*b).clone()*(&pol_1);
    }
    println!("{:?}",num0_2);
    println!("{:?}",in2_0);

    //gatebootstrapping have problems, so no test here


    //test greater_hcmp:if in1_0's number > in2_0's number, then it will give back encrypted 1, otherwise -1(I use 2 and 1 to show)
    let out1 = comparison::greater_hcmp(&in1_0,&in2_0);
    let out1_a=out1.a();
    let mut sum1 = FF::new(0);
    for i in 0..1024{
        sum1 = sum1 +code[i]*out1_a[i];
    }
    let decoded_value1 = decode(out1.b()-sum1);
    assert_eq!(1,decoded_value1);

    //test equality_hcmp:if in1_0's number = in2_0's number, then it will give back encrypted 1, otherwise -1
    let in1_1=comparison::rlwe_turn(num1_1,2);
    let in2_1=comparison::rgsw_turn(num2_1,2);
    let out2 = comparison::equality_hcmp(&in1_1,&in2_1);
    let out2_a=out2.a();
    let mut sum2 = FF::new(0);
    for i in 0..1024{
        sum2 = sum2 +code[i]*out2_a[i];
    }
    let decoded_value2 = decode(out2.b()-sum2);
    assert_eq!(1,decoded_value2);

    //test greater_hcmp:if in1_0's number > in2_0's number, then it will give back encrypted 1, otherwise -1
    let in1_2=comparison::rlwe_turn(num1_2,1);
    let in2_2=comparison::rgsw_turn(num2_2,2);
    let out3 = comparison::less_hcmp(&in1_2,&in2_2);
    let out3_a=out3.a();
    let mut sum3 = FF::new(0);
    for i in 0..1024{
        sum3 = sum3 +code[i]*out3_a[i];
    }
    let decoded_value3 = decode(out3.b()-sum3);
    assert_eq!(1,decoded_value3);


}
*/
