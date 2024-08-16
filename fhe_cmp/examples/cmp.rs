use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
   DecomposableField, Field,
};
use fhe_cmp::comparison::{self, initial};
use fhe_core::{
    BlindRotationType, ConstParameters, ModulusSwitchRoundMethod, Parameters, RLWEBlindRotationKey,
    RingSecretKeyType, SecretKeyPack, SecretKeyType, StepsAfterBR,
};
use num_traits::Zero;
use rand::prelude::*;

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct FF(u64);
type Inner = u64; // inner type
const FP: Inner = FF::MODULUS_VALUE; // ciphertext space
const FT: Inner = 16; // message space
const DEELTA: FF = FF((FP as f64 / FT as f64) as Inner);
const HALF_DEELTA: FF = FF((FP as f64 / (FT as f64 * 2.0)) as Inner);

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
for i in 0..10{
    let rotationkey = RLWEBlindRotationKey::generate(&sk, sampler, &mut rng);
    let x = rng.gen_range(0..100000);
    let y = rng.gen_range(0..100000);
    let (value1,value2) = initial(
        x, 
        y, 
        param.ring_dimension(),
        sk.ntt_ring_secret_key(),
        sampler,
        &mut rng,
        basis,
        poly_length,
        HALF_DEELTA,
    );
    let out1 = comparison::less_arbhcmp(&value1, &value2, &rotationkey, DEELTA, HALF_DEELTA, poly_length);
    let out2 = comparison::equality_arbhcmp(&value1,&value2, &rotationkey,poly_length);
    let out3 = comparison::greater_arbhcmp(&value1, &value2, &rotationkey, DEELTA, HALF_DEELTA, poly_length);
    let a_mul_s1 = rlwe_sk
        .iter()
        .zip(out1.a())
        .fold(FF::zero(), |acc, (&s, &a)| acc + s * a);
    let a_mul_s2 = rlwe_sk
        .iter()
        .zip(out2.a())
        .fold(FF::zero(), |acc, (&s, &a)| acc + s * a);
    let a_mul_s3 = rlwe_sk
        .iter()
        .zip(out3.a())
        .fold(FF::zero(), |acc, (&s, &a)| acc + s * a);
    let decoded_value1 = decode(out1.b() - a_mul_s1);
    let decoded_value2 = decode(out2.b() - a_mul_s2);
    let decoded_value3 = decode(out3.b() - a_mul_s3);
    if x < y {
        if decoded_value1 != 1 || decoded_value2 != 0 || decoded_value3 != 0{
            println!("{},{}",x,y);
            println!("error1!");
        }
    }else if x == y {
        if decoded_value1 != 0 || decoded_value2 != 1 || decoded_value3 != 0{
            println!("{},{}",x,y);
            println!("error2!");
        }
    }else{
        if decoded_value1 != 0 || decoded_value2 != 0 || decoded_value3 != 1{
            println!("{},{}",x,y);
            println!("error3!");
        }
    }
    println!("{}",i);
}

}

