mod comparison;
use algebra::{derive::{DecomposableField, FheField, Field, Prime, NTT},Basis,DecomposableField, Field,
    Polynomial, NTTPolynomial};
use lattice::{NTTRGSW, NTTRLWE,RLWE};
use rand::prelude::*;
use fhe_core::{BlindRotationType, ConstParameters, ModulusSwitchRoundMethod, Parameters, RingSecretKeyType,
    SecretKeyPack, SecretKeyType, StepsAfterBR,lwe_modulus_switch};

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct FF(u32);
pub type RingSecretKey<FF> = Polynomial<FF>;
pub type NTTRingSecretKey<FF> = NTTPolynomial<FF>;

type Inner = u32; // inner type

const FP: Inner = FF::MODULUS_VALUE; // ciphertext space
const FT: Inner = 4; // message space

#[inline]
fn encode(m: Inner) -> FF {
    FF::new((m as f64 * FP as f64 / FT as f64).round() as Inner)
}

#[inline]
fn decode(c: FF) -> Inner {
    (c.value() as f64 * FT as f64 / FP as f64).round() as Inner % FT
}

fn main(){
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
    let sampler = param.ring_noise_distribution();
    let ntt_num1=NTTRLWE::generate_random_value_sample(sk.ntt_ring_secret_key(),encode(value),sampler,&mut rng);
    let num2 =NTTRGSW::generate_random_one_sample(sk.ntt_ring_secret_key(), basis, sampler, &mut rng);
    let num1=RLWE::from(ntt_num1);
    /*let multi = num1.mul_ntt_rgsw(&num2);
    let dec = multi.b() - multi.a() * sk.ntt_ring_secret_key();
    let dec_value = dec[0];
    let decoded_value = decode(dec_value);
    println!("{}",decoded_value);
*/
    let in1=comparison::rlwe_turn(num1,4);
    let in2=comparison::rgsw_turn(num2,2);
    let out = comparison::greater_hcmp(&in1,&in2);
    //let out = comparison::greater_hcmp(&num1,&num2);
    let dec = out.b() - out.a() * sk.ntt_ring_secret_key();
    let dec_value = -dec[0];
    let decoded_value = decode(dec_value);
    println!("{}",decoded_value);
}
