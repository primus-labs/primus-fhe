use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial};
use fhe_cmp::{
    compare::{decrypt, encrypt, HomeCmpScheme},
    parameters::{DEFAULT_PARAMETERS, DELTA, FF, HALF_DELTA},
};
use fhe_core::{Parameters, RLWEBlindRotationKey, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use once_cell::sync::OnceCell;
use rand::prelude::*;
static mut INSTANCE: OnceCell<InitializationData> = OnceCell::new();

struct InitializationData {
    param: Parameters<u64, FF>,
    sk: SecretKeyPack<u64, FF>,
    rotationkey: HomeCmpScheme<u64, FF>,
    value1_hcmp_1: Vec<RLWE<FF>>,
    value2_hcmp_1: Vec<NTTRGSW<FF>>,
    value1_hcmp_2: Vec<RLWE<FF>>,
    value2_hcmp_2: Vec<NTTRGSW<FF>>,
    value1_hcmp_3: Vec<RLWE<FF>>,
    value2_hcmp_3: Vec<NTTRGSW<FF>>,
    value1_arbhcmp_1: Vec<RLWE<FF>>,
    value2_arbhcmp_1: Vec<NTTRGSW<FF>>,
    value1_arbhcmp_2: Vec<RLWE<FF>>,
    value2_arbhcmp_2: Vec<NTTRGSW<FF>>,
    value1_arbhcmp_3: Vec<RLWE<FF>>,
    value2_arbhcmp_3: Vec<NTTRGSW<FF>>,
}

fn init() {
    unsafe {
        INSTANCE.get_or_init(|| {
            let mut rng = thread_rng();
            let param = *DEFAULT_PARAMETERS;
            let sk = SecretKeyPack::new(param);
            let basis = param.blind_rotation_basis();
            let sampler = param.ring_noise_distribution();
            let rotationkey = HomeCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
            let x_hcmp_1 = rng.gen_range(1..1024);
            let y_hcmp_1 = rng.gen_range(0..x_hcmp_1);
            let x_hcmp_2 = rng.gen_range(1..1024);
            let y_hcmp_2 = x_hcmp_2;
            let y_hcmp_3 = rng.gen_range(1..1024);
            let x_hcmp_3 = rng.gen_range(0..y_hcmp_3);
            let x_arbhcmp_1 = rng.gen_range(1025..10000);
            let y_arbhcmp_1 = rng.gen_range(0..x_arbhcmp_1);
            let x_arbhcmp_2 = rng.gen_range(1025..10000);
            let y_arbhcmp_2 = x_arbhcmp_2;
            let y_arbhcmp_3 = rng.gen_range(1025..10000);
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

            InitializationData {
                param,
                sk,
                rotationkey,
                value1_hcmp_1,
                value2_hcmp_1,
                value1_hcmp_2,
                value2_hcmp_2,
                value1_hcmp_3,
                value2_hcmp_3,
                value1_arbhcmp_1,
                value1_arbhcmp_2,
                value1_arbhcmp_3,
                value2_arbhcmp_1,
                value2_arbhcmp_2,
                value2_arbhcmp_3,
            }
        });
    }
}

#[test]
fn test_gt_hcmp() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let gt_cipher_1 = data
        .rotationkey
        .gt_hcmp(&data.value1_hcmp_1[0], &data.value2_hcmp_1[0]);
    let gt_cipher_2 = data
        .rotationkey
        .gt_hcmp(&data.value1_hcmp_2[0], &data.value2_hcmp_2[0]);
    let gt_cipher_3 = data
        .rotationkey
        .gt_hcmp(&data.value1_hcmp_3[0], &data.value2_hcmp_3[0]);
    let gt_value_1 = decrypt(rlwe_sk, gt_cipher_1);
    let gt_value_2 = decrypt(rlwe_sk, gt_cipher_2);
    let gt_value_3 = decrypt(rlwe_sk, gt_cipher_3);
    assert_eq!(gt_value_1, 1);
    assert_eq!(gt_value_2, data.param.lwe_plain_modulus() - 1);
    assert_eq!(gt_value_3, data.param.lwe_plain_modulus() - 1);
}

#[test]
fn test_eq_hcmp() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let eq_cipher_1 = data
        .rotationkey
        .eq_hcmp(&data.value1_hcmp_1[0], &data.value2_hcmp_1[0]);
    let eq_cipher_2 = data
        .rotationkey
        .eq_hcmp(&data.value1_hcmp_2[0], &data.value2_hcmp_2[0]);
    let eq_cipher_3 = data
        .rotationkey
        .eq_hcmp(&data.value1_hcmp_3[0], &data.value2_hcmp_3[0]);
    let eq_value_1 = decrypt(rlwe_sk, eq_cipher_1);
    let eq_value_2 = decrypt(rlwe_sk, eq_cipher_2);
    let eq_value_3 = decrypt(rlwe_sk, eq_cipher_3);
    assert_eq!(eq_value_1, data.param.lwe_plain_modulus() - 1);
    assert_eq!(eq_value_2, 1);
    assert_eq!(eq_value_3, data.param.lwe_plain_modulus() - 1);
}

#[test]
fn test_lt_hcmp() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let lt_cipher_1 = data
        .rotationkey
        .lt_hcmp(&data.value1_hcmp_1[0], &data.value2_hcmp_1[0]);
    let lt_cipher_2 = data
        .rotationkey
        .lt_hcmp(&data.value1_hcmp_2[0], &data.value2_hcmp_2[0]);
    let lt_cipher_3 = data
        .rotationkey
        .lt_hcmp(&data.value1_hcmp_3[0], &data.value2_hcmp_3[0]);
    let lt_value_1 = decrypt(rlwe_sk, lt_cipher_1);
    let lt_value_2 = decrypt(rlwe_sk, lt_cipher_2);
    let lt_value_3 = decrypt(rlwe_sk, lt_cipher_3);
    assert_eq!(lt_value_1, data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_2, data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_3, 1);
}

#[test]
fn test_homand() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let sampler = data.param.ring_noise_distribution();
    let mut rng = thread_rng();
    let poly_length = data.param.ring_dimension();
    let lwe_delta = lwe_generate(
        rlwe_sk,
        data.param.ring_dimension(),
        sampler,
        &mut rng,
        DELTA,
    );
    let lwe_delta_neg = lwe_generate_neg(
        rlwe_sk,
        data.param.ring_dimension(),
        sampler,
        &mut rng,
        DELTA,
    );
    let homand_cipher1 = data
        .rotationkey
        .homand(&lwe_delta, &lwe_delta, poly_length, DELTA);
    let homand_cipher2 = data
        .rotationkey
        .homand(&lwe_delta, &lwe_delta_neg, poly_length, DELTA);
    let homand_cipher3 = data
        .rotationkey
        .homand(&lwe_delta_neg, &lwe_delta, poly_length, DELTA);
    let homand_cipher4 =
        data.rotationkey
            .homand(&lwe_delta_neg, &lwe_delta_neg, poly_length, DELTA);
    let output1 = decrypt(rlwe_sk, homand_cipher1);
    let output2 = decrypt(rlwe_sk, homand_cipher2);
    let output3 = decrypt(rlwe_sk, homand_cipher3);
    let output4 = decrypt(rlwe_sk, homand_cipher4);
    assert_eq!(output1, 1);
    assert_eq!(output2, data.param.lwe_plain_modulus() - 1);
    assert_eq!(output3, data.param.lwe_plain_modulus() - 1);
    assert_eq!(output4, data.param.lwe_plain_modulus() - 1);
}

#[test]
fn test_gt_arbhcmp() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let gt_cipher_1 = data.rotationkey.gt_arbhcmp(
        &data.value1_arbhcmp_1,
        &data.value2_arbhcmp_1,
        DELTA,
        HALF_DELTA,
        data.param.ring_dimension(),
    );
    let gt_cipher_2 = data.rotationkey.gt_arbhcmp(
        &data.value1_arbhcmp_2,
        &data.value2_arbhcmp_2,
        DELTA,
        HALF_DELTA,
        data.param.ring_dimension(),
    );
    let gt_cipher_3 = data.rotationkey.gt_arbhcmp(
        &data.value1_arbhcmp_3,
        &data.value2_arbhcmp_3,
        DELTA,
        HALF_DELTA,
        data.param.ring_dimension(),
    );
    let gt_value_1 = decrypt(rlwe_sk, gt_cipher_1);
    let gt_value_2 = decrypt(rlwe_sk, gt_cipher_2);
    let gt_value_3 = decrypt(rlwe_sk, gt_cipher_3);
    assert_eq!(gt_value_1, 1);
    assert_eq!(gt_value_2, data.param.lwe_plain_modulus() - 1);
    assert_eq!(gt_value_3, data.param.lwe_plain_modulus() - 1);
}

#[test]
fn test_eq_arbhcmp() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let eq_cipher_1 = data.rotationkey.eq_arbhcmp(
        &data.value1_arbhcmp_1,
        &data.value2_arbhcmp_1,
        data.param.ring_dimension(),
        DELTA,
    );
    let eq_cipher_2 = data.rotationkey.eq_arbhcmp(
        &data.value1_arbhcmp_2,
        &data.value2_arbhcmp_2,
        data.param.ring_dimension(),
        DELTA,
    );
    let eq_cipher_3 = data.rotationkey.eq_arbhcmp(
        &data.value1_arbhcmp_3,
        &data.value2_arbhcmp_3,
        data.param.ring_dimension(),
        DELTA,
    );
    let eq_value_1 = decrypt(rlwe_sk, eq_cipher_1);
    let eq_value_2 = decrypt(rlwe_sk, eq_cipher_2);
    let eq_value_3 = decrypt(rlwe_sk, eq_cipher_3);
    assert_eq!(eq_value_1, data.param.lwe_plain_modulus() - 1);
    assert_eq!(eq_value_2, 1);
    assert_eq!(eq_value_3, data.param.lwe_plain_modulus() - 1);
}

#[test]
fn test_lt_arbhcmp() {
    init();
    let data = unsafe { INSTANCE.get().unwrap() };
    let rlwe_sk = data.sk.ring_secret_key().as_slice();
    let lt_cipher_1 = data.rotationkey.lt_arbhcmp(
        &data.value1_arbhcmp_1,
        &data.value2_arbhcmp_1,
        DELTA,
        HALF_DELTA,
        data.param.ring_dimension(),
    );
    let lt_cipher_2 = data.rotationkey.lt_arbhcmp(
        &data.value1_arbhcmp_2,
        &data.value2_arbhcmp_2,
        DELTA,
        HALF_DELTA,
        data.param.ring_dimension(),
    );
    let lt_cipher_3 = data.rotationkey.lt_arbhcmp(
        &data.value1_arbhcmp_3,
        &data.value2_arbhcmp_3,
        DELTA,
        HALF_DELTA,
        data.param.ring_dimension(),
    );
    let lt_value_1 = decrypt(rlwe_sk, lt_cipher_1);
    let lt_value_2 = decrypt(rlwe_sk, lt_cipher_2);
    let lt_value_3 = decrypt(rlwe_sk, lt_cipher_3);
    assert_eq!(lt_value_1, data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_2, data.param.lwe_plain_modulus() - 1);
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
