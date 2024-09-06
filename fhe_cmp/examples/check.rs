use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial};
use fhe_cmp::{
    compare::{decrypt, encrypt, HomCmpScheme},
    parameters::{DEFAULT_PARAMERTERS, DELTA, HALF_DELTA},
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use lattice::LWE;
use rand::prelude::*;
use std::cmp::Ordering;
fn main() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x = rng.gen_range(1025..100000);
    let y = rng.gen_range(1025..100000);
    let x_hcmp = rng.gen_range(0..1024);
    let y_hcmp = rng.gen_range(0..1024);
    let poly_length = param.ring_dimension();
    let (value1, value2) = encrypt(
        x,
        y,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp, value2_hcmp) = encrypt(
        x_hcmp,
        y_hcmp,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );

    //test hcmp
    println!("test hcmp");
    let gt_cipher = rotationkey.gt_hcmp(&value1_hcmp[0], &value2_hcmp[0]);
    let eq_cipher = rotationkey.eq_hcmp(&value1_hcmp[0], &value2_hcmp[0]);
    let lt_cipher = rotationkey.lt_hcmp(&value1_hcmp[0], &value2_hcmp[0]);
    let gt_value = decrypt(rlwe_sk, gt_cipher);
    let eq_value = decrypt(rlwe_sk, eq_cipher);
    let lt_value = decrypt(rlwe_sk, lt_cipher);
    match x_hcmp.cmp(&y_hcmp) {
        Ordering::Greater => {
            assert_eq!(gt_value, 1);
            assert_eq!(eq_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Equal => {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(eq_value, 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Less => {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, 1);
        }
    }
    println!("finish hcmp test");

    //test arbhcmp
    println!("test arbhcmp");
    let gt_cipher = rotationkey.gt_arbhcmp(&value1, &value2, DELTA, HALF_DELTA, poly_length);
    let eq_cipher = rotationkey.eq_arbhcmp(&value1, &value2, poly_length, DELTA);
    let lt_cipher = rotationkey.lt_arbhcmp(&value1, &value2, DELTA, HALF_DELTA, poly_length);
    let gt_value = decrypt(rlwe_sk, gt_cipher);
    let eq_value = decrypt(rlwe_sk, eq_cipher);
    let lt_value = decrypt(rlwe_sk, lt_cipher);
    match x.cmp(&y) {
        Ordering::Greater => {
            assert_eq!(gt_value, 1);
            assert_eq!(eq_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Equal => {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(eq_value, 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Less => {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, 1);
        }
    }
    println!("finish arbhcmp test");

    //test homand only when 2 delta comes out delta
    println!("test homand");
    let lwe_delta = lwe_generate(rlwe_sk, param.ring_dimension(), sampler, &mut rng, DELTA);
    let lwe_delta_neg = lwe_generate_neg(rlwe_sk, param.ring_dimension(), sampler, &mut rng, DELTA);
    let homand_cipher1 = rotationkey.homand(&lwe_delta, &lwe_delta, poly_length, DELTA);
    let homand_cipher2 = rotationkey.homand(&lwe_delta, &lwe_delta_neg, poly_length, DELTA);
    let homand_cipher3 = rotationkey.homand(&lwe_delta_neg, &lwe_delta, poly_length, DELTA);
    let homand_cipher4 = rotationkey.homand(&lwe_delta_neg, &lwe_delta_neg, poly_length, DELTA);
    let output1 = decrypt(rlwe_sk, homand_cipher1);
    let output2 = decrypt(rlwe_sk, homand_cipher2);
    let output3 = decrypt(rlwe_sk, homand_cipher3);
    let output4 = decrypt(rlwe_sk, homand_cipher4);
    assert_eq!(output1, 1);
    assert_eq!(output2, param.lwe_plain_modulus() - 1);
    assert_eq!(output3, param.lwe_plain_modulus() - 1);
    assert_eq!(output4, param.lwe_plain_modulus() - 1);
    println!("fininsh homand test");
}

///generate LWE ciphertext which encrypts 1
pub fn lwe_generate<F, R>(
    secret_key: &[F],
    rlwe_dimension: usize,
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
    delta: F,
) -> LWE<F>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let a = Polynomial::random(rlwe_dimension, &mut rng);
    let a_mul_s = secret_key
        .iter()
        .zip(a.clone())
        .fold(F::zero(), |acc, (&s, a)| acc + s * a);
    let mut e_a = error_sampler.sample(&mut rng);
    e_a += a_mul_s + delta;
    LWE::new(a.data(), e_a)
}

///generate LWE ciphertext which encrypts -1
pub fn lwe_generate_neg<F, R>(
    secret_key: &[F],
    rlwe_dimension: usize,
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
    delta: F,
) -> LWE<F>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let a = Polynomial::random(rlwe_dimension, &mut rng);
    let a_mul_s = secret_key
        .iter()
        .zip(a.clone())
        .fold(F::zero(), |acc, (&s, a)| acc + s * a);
    let mut e_a = error_sampler.sample(&mut rng);
    e_a += a_mul_s - delta;
    LWE::new(a.data(), e_a)
}
