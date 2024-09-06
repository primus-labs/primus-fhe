use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial};
use fhe_cmp::{
    compare::{decrypt, encrypt, HomeCmpScheme},
    parameters::{DEFAULT_PARAMETERS, DELTA, HALF_DELTA},
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use lattice::LWE;
use rand::prelude::*;

#[test]
fn test_gt_hcmp() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x_hcmp_1 = rng.gen_range(1..1024);
    let y_hcmp_1 = rng.gen_range(0..x_hcmp_1);
    let x_hcmp_2 = rng.gen_range(1..1024);
    let y_hcmp_2 = x_hcmp_2;
    let y_hcmp_3 = rng.gen_range(1..1024);
    let x_hcmp_3 = rng.gen_range(0..y_hcmp_3);
    let (value1_hcmp_1, value2_hcmp_1) = encrypt(
        x_hcmp_1,
        y_hcmp_1,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp_2, value2_hcmp_2) = encrypt(
        x_hcmp_2,
        y_hcmp_2,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp_3, value2_hcmp_3) = encrypt(
        x_hcmp_3,
        y_hcmp_3,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let gt_cipher_1 = rotationkey.gt_hcmp(&value1_hcmp_1[0], &value2_hcmp_1[0]);
    let gt_cipher_2 = rotationkey.gt_hcmp(&value1_hcmp_2[0], &value2_hcmp_2[0]);
    let gt_cipher_3 = rotationkey.gt_hcmp(&value1_hcmp_3[0], &value2_hcmp_3[0]);
    let gt_value_1 = decrypt(rlwe_sk, gt_cipher_1);
    let gt_value_2 = decrypt(rlwe_sk, gt_cipher_2);
    let gt_value_3 = decrypt(rlwe_sk, gt_cipher_3);
    assert_eq!(gt_value_1, 1);
    assert_eq!(gt_value_2, param.lwe_plain_modulus() - 1);
    assert_eq!(gt_value_3, param.lwe_plain_modulus() - 1);
}

#[test]
fn test_eq_hcmp() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x_hcmp_1 = rng.gen_range(1..1024);
    let y_hcmp_1 = rng.gen_range(0..x_hcmp_1);
    let x_hcmp_2 = rng.gen_range(1..1024);
    let y_hcmp_2 = x_hcmp_2;
    let y_hcmp_3 = rng.gen_range(1..1024);
    let x_hcmp_3 = rng.gen_range(0..y_hcmp_3);
    let (value1_hcmp_1, value2_hcmp_1) = encrypt(
        x_hcmp_1,
        y_hcmp_1,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp_2, value2_hcmp_2) = encrypt(
        x_hcmp_2,
        y_hcmp_2,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp_3, value2_hcmp_3) = encrypt(
        x_hcmp_3,
        y_hcmp_3,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let eq_cipher_1 = rotationkey.eq_hcmp(&value1_hcmp_1[0], &value2_hcmp_1[0]);
    let eq_cipher_2 = rotationkey.eq_hcmp(&value1_hcmp_2[0], &value2_hcmp_2[0]);
    let eq_cipher_3 = rotationkey.eq_hcmp(&value1_hcmp_3[0], &value2_hcmp_3[0]);
    let eq_value_1 = decrypt(rlwe_sk, eq_cipher_1);
    let eq_value_2 = decrypt(rlwe_sk, eq_cipher_2);
    let eq_value_3 = decrypt(rlwe_sk, eq_cipher_3);
    assert_eq!(eq_value_1, param.lwe_plain_modulus() - 1);
    assert_eq!(eq_value_2, 1);
    assert_eq!(eq_value_3, param.lwe_plain_modulus() - 1);
}

#[test]
fn test_lt_hcmp() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x_hcmp_1 = rng.gen_range(1..1024);
    let y_hcmp_1 = rng.gen_range(0..x_hcmp_1);
    let x_hcmp_2 = rng.gen_range(1..1024);
    let y_hcmp_2 = x_hcmp_2;
    let y_hcmp_3 = rng.gen_range(1..1024);
    let x_hcmp_3 = rng.gen_range(0..y_hcmp_3);
    let (value1_hcmp_1, value2_hcmp_1) = encrypt(
        x_hcmp_1,
        y_hcmp_1,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp_2, value2_hcmp_2) = encrypt(
        x_hcmp_2,
        y_hcmp_2,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_hcmp_3, value2_hcmp_3) = encrypt(
        x_hcmp_3,
        y_hcmp_3,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let lt_cipher_1 = rotationkey.lt_hcmp(&value1_hcmp_1[0], &value2_hcmp_1[0]);
    let lt_cipher_2 = rotationkey.lt_hcmp(&value1_hcmp_2[0], &value2_hcmp_2[0]);
    let lt_cipher_3 = rotationkey.lt_hcmp(&value1_hcmp_3[0], &value2_hcmp_3[0]);
    let lt_value_1 = decrypt(rlwe_sk, lt_cipher_1);
    let lt_value_2 = decrypt(rlwe_sk, lt_cipher_2);
    let lt_value_3 = decrypt(rlwe_sk, lt_cipher_3);
    assert_eq!(lt_value_1, param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_2, param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_3, 1);
}

#[test]
fn test_homand() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let poly_length = param.ring_dimension();
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
}

#[test]
fn test_gt_arbhcmp() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x_arbhcmp_1 = rng.gen();
    let y_arbhcmp_1 = rng.gen_range(0..x_arbhcmp_1);
    let x_arbhcmp_2 = rng.gen();
    let y_arbhcmp_2 = x_arbhcmp_2;
    let y_arbhcmp_3 = rng.gen();
    let x_arbhcmp_3 = rng.gen_range(0..y_arbhcmp_3);
    let (value1_arbhcmp_1, value2_arbhcmp_1) = encrypt(
        x_arbhcmp_1,
        y_arbhcmp_1,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_arbhcmp_2, value2_arbhcmp_2) = encrypt(
        x_arbhcmp_2,
        y_arbhcmp_2,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_arbhcmp_3, value2_arbhcmp_3) = encrypt(
        x_arbhcmp_3,
        y_arbhcmp_3,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let gt_cipher_1 = rotationkey.gt_arbhcmp(
        &value1_arbhcmp_1,
        &value2_arbhcmp_1,
        DELTA,
        HALF_DELTA,
        param.ring_dimension(),
    );
    let gt_cipher_2 = rotationkey.gt_arbhcmp(
        &value1_arbhcmp_2,
        &value2_arbhcmp_2,
        DELTA,
        HALF_DELTA,
        param.ring_dimension(),
    );
    let gt_cipher_3 = rotationkey.gt_arbhcmp(
        &value1_arbhcmp_3,
        &value2_arbhcmp_3,
        DELTA,
        HALF_DELTA,
        param.ring_dimension(),
    );
    let gt_value_1 = decrypt(rlwe_sk, gt_cipher_1);
    let gt_value_2 = decrypt(rlwe_sk, gt_cipher_2);
    let gt_value_3 = decrypt(rlwe_sk, gt_cipher_3);
    assert_eq!(gt_value_1, 1);
    assert_eq!(gt_value_2, param.lwe_plain_modulus() - 1);
    assert_eq!(gt_value_3, param.lwe_plain_modulus() - 1);
}

#[test]
fn test_eq_arbhcmp() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x_arbhcmp_1 = rng.gen();
    let y_arbhcmp_1 = rng.gen_range(0..x_arbhcmp_1);
    let x_arbhcmp_2 = rng.gen();
    let y_arbhcmp_2 = x_arbhcmp_2;
    let y_arbhcmp_3 = rng.gen();
    let x_arbhcmp_3 = rng.gen_range(0..y_arbhcmp_3);
    let (value1_arbhcmp_1, value2_arbhcmp_1) = encrypt(
        x_arbhcmp_1,
        y_arbhcmp_1,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_arbhcmp_2, value2_arbhcmp_2) = encrypt(
        x_arbhcmp_2,
        y_arbhcmp_2,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_arbhcmp_3, value2_arbhcmp_3) = encrypt(
        x_arbhcmp_3,
        y_arbhcmp_3,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let eq_cipher_1 = rotationkey.eq_arbhcmp(
        &value1_arbhcmp_1,
        &value2_arbhcmp_1,
        param.ring_dimension(),
        DELTA,
    );
    let eq_cipher_2 = rotationkey.eq_arbhcmp(
        &value1_arbhcmp_2,
        &value2_arbhcmp_2,
        param.ring_dimension(),
        DELTA,
    );
    let eq_cipher_3 = rotationkey.eq_arbhcmp(
        &value1_arbhcmp_3,
        &value2_arbhcmp_3,
        param.ring_dimension(),
        DELTA,
    );
    let eq_value_1 = decrypt(rlwe_sk, eq_cipher_1);
    let eq_value_2 = decrypt(rlwe_sk, eq_cipher_2);
    let eq_value_3 = decrypt(rlwe_sk, eq_cipher_3);
    assert_eq!(eq_value_1, param.lwe_plain_modulus() - 1);
    assert_eq!(eq_value_2, 1);
    assert_eq!(eq_value_3, param.lwe_plain_modulus() - 1);
}

#[test]
fn test_lt_arbhcmp() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    let x_arbhcmp_1 = rng.gen();
    let y_arbhcmp_1 = rng.gen_range(0..x_arbhcmp_1);
    let x_arbhcmp_2 = rng.gen();
    let y_arbhcmp_2 = x_arbhcmp_2;
    let y_arbhcmp_3 = rng.gen();
    let x_arbhcmp_3 = rng.gen_range(0..y_arbhcmp_3);
    let (value1_arbhcmp_1, value2_arbhcmp_1) = encrypt(
        x_arbhcmp_1,
        y_arbhcmp_1,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_arbhcmp_2, value2_arbhcmp_2) = encrypt(
        x_arbhcmp_2,
        y_arbhcmp_2,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let (value1_arbhcmp_3, value2_arbhcmp_3) = encrypt(
        x_arbhcmp_3,
        y_arbhcmp_3,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let lt_cipher_1 = rotationkey.lt_arbhcmp(
        &value1_arbhcmp_1,
        &value2_arbhcmp_1,
        DELTA,
        HALF_DELTA,
        param.ring_dimension(),
    );
    let lt_cipher_2 = rotationkey.lt_arbhcmp(
        &value1_arbhcmp_2,
        &value2_arbhcmp_2,
        DELTA,
        HALF_DELTA,
        param.ring_dimension(),
    );
    let lt_cipher_3 = rotationkey.lt_arbhcmp(
        &value1_arbhcmp_3,
        &value2_arbhcmp_3,
        DELTA,
        HALF_DELTA,
        param.ring_dimension(),
    );
    let lt_value_1 = decrypt(rlwe_sk, lt_cipher_1);
    let lt_value_2 = decrypt(rlwe_sk, lt_cipher_2);
    let lt_value_3 = decrypt(rlwe_sk, lt_cipher_3);
    assert_eq!(lt_value_1, param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_2, param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_3, 1);
}

fn lwe_generate<F, R>(
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

fn lwe_generate_neg<F, R>(
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
