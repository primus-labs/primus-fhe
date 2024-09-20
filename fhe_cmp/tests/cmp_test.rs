use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial};
use fhe_cmp::{
    compare::{decrypt, Encryptor, HomomorphicCmpScheme},
    parameters::{DEFAULT_PARAMETERS, DELTA, FF},
};
use fhe_core::{Parameters, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use once_cell::sync::OnceCell;
use rand::prelude::*;
static mut INSTANCE_PARAM: OnceCell<InitializationDataParam> = OnceCell::new();
static mut INSTANCE_CIPHER: OnceCell<InitializationDataCipher> = OnceCell::new();

struct InitializationDataParam {
    sk: SecretKeyPack<u64, FF>,
    rotationkey: HomomorphicCmpScheme<u64, FF>,
    param: Parameters<u64, FF>,
}

struct InitializationDataCipher {
    rlwe_hcmpcipher_great: Vec<RLWE<FF>>,
    rgsw_hcmpcipher_great: Vec<NTTRGSW<FF>>,
    rlwe_hcmpcipher_small: Vec<RLWE<FF>>,
    rgsw_hcmpcipher_small: Vec<NTTRGSW<FF>>,
    rlwe_arbhcmpcipher_great: Vec<RLWE<FF>>,
    rgsw_arbhcmpcipher_great: Vec<NTTRGSW<FF>>,
    rlwe_arbhcmpcipher_small: Vec<RLWE<FF>>,
    rgsw_arbhcmpcipher_small: Vec<NTTRGSW<FF>>,
}

fn init_param() {
    unsafe {
        INSTANCE_PARAM.get_or_init(|| {
            let param = *DEFAULT_PARAMETERS;
            let sk = SecretKeyPack::new(param);
            let rotationkey = HomomorphicCmpScheme::new(&sk);
            InitializationDataParam {
                sk,
                rotationkey,
                param,
            }
        });
    }
}

fn init_cipher() {
    unsafe {
        INSTANCE_CIPHER.get_or_init(|| {
            init_param();
            let param_data = INSTANCE_PARAM.get().unwrap();
            let mut rng = thread_rng();
            let hcmp_great = 10;
            let hcmp_small = 5;
            let arbhcmp_great = 1030;
            let arbhcmp_small = 1025;
            let enc_elements = Encryptor::new(&param_data.sk);
            let value1_hcmp_great = enc_elements.rlwe_encrypt(hcmp_great, &mut rng);
            let value1_hcmp_small = enc_elements.rlwe_encrypt(hcmp_small, &mut rng);
            let value2_hcmp_great = enc_elements.rgsw_encrypt(hcmp_great, &mut rng);
            let value2_hcmp_small = enc_elements.rgsw_encrypt(hcmp_small, &mut rng);
            let value1_arbhcmp_great = enc_elements.rlwe_encrypt(arbhcmp_great, &mut rng);
            let value1_arbhcmp_small = enc_elements.rlwe_encrypt(arbhcmp_small, &mut rng);
            let value2_arbhcmp_great = enc_elements.rgsw_encrypt(arbhcmp_great, &mut rng);
            let value2_arbhcmp_small = enc_elements.rgsw_encrypt(arbhcmp_small, &mut rng);
            InitializationDataCipher {
                rlwe_hcmpcipher_great: value1_hcmp_great,
                rgsw_hcmpcipher_great: value2_hcmp_great,
                rlwe_hcmpcipher_small: value1_hcmp_small,
                rgsw_hcmpcipher_small: value2_hcmp_small,
                rlwe_arbhcmpcipher_great: value1_arbhcmp_great,
                rgsw_arbhcmpcipher_great: value2_arbhcmp_great,
                rlwe_arbhcmpcipher_small: value1_arbhcmp_small,
                rgsw_arbhcmpcipher_small: value2_arbhcmp_small,
            }
        });
    }
}

#[test]
#[ignore = "slow"]
fn test_gt_hcmp() {
    init_param();
    init_cipher();
    let data = unsafe { INSTANCE_CIPHER.get().unwrap() };
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let gt_cipher_1 = param_data.rotationkey.gt_hcmp(
        &data.rlwe_hcmpcipher_great[0],
        &data.rgsw_hcmpcipher_small[0],
    );
    let gt_cipher_2 = param_data.rotationkey.gt_hcmp(
        &data.rlwe_hcmpcipher_great[0],
        &data.rgsw_hcmpcipher_great[0],
    );
    let gt_cipher_3 = param_data.rotationkey.gt_hcmp(
        &data.rlwe_hcmpcipher_small[0],
        &data.rgsw_hcmpcipher_great[0],
    );
    let gt_value_1 = decrypt(rlwe_sk, gt_cipher_1);
    let gt_value_2 = decrypt(rlwe_sk, gt_cipher_2);
    let gt_value_3 = decrypt(rlwe_sk, gt_cipher_3);
    assert_eq!(gt_value_1, 1);
    assert_eq!(gt_value_2, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(gt_value_3, param_data.param.lwe_plain_modulus() - 1);
}

#[test]
#[ignore = "slow"]
fn test_eq_hcmp() {
    init_param();
    init_cipher();
    let data = unsafe { INSTANCE_CIPHER.get().unwrap() };
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let eq_cipher_1 = param_data.rotationkey.eq_hcmp(
        &data.rlwe_hcmpcipher_great[0],
        &data.rgsw_hcmpcipher_small[0],
    );
    let eq_cipher_2 = param_data.rotationkey.eq_hcmp(
        &data.rlwe_hcmpcipher_great[0],
        &data.rgsw_hcmpcipher_great[0],
    );
    let eq_cipher_3 = param_data.rotationkey.eq_hcmp(
        &data.rlwe_hcmpcipher_small[0],
        &data.rgsw_hcmpcipher_great[0],
    );
    let eq_value_1 = decrypt(rlwe_sk, eq_cipher_1);
    let eq_value_2 = decrypt(rlwe_sk, eq_cipher_2);
    let eq_value_3 = decrypt(rlwe_sk, eq_cipher_3);
    assert_eq!(eq_value_1, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(eq_value_2, 1);
    assert_eq!(eq_value_3, param_data.param.lwe_plain_modulus() - 1);
}

#[test]
#[ignore = "slow"]
fn test_lt_hcmp() {
    init_param();
    init_cipher();
    let data = unsafe { INSTANCE_CIPHER.get().unwrap() };
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let lt_cipher_1 = param_data.rotationkey.lt_hcmp(
        &data.rlwe_hcmpcipher_great[0],
        &data.rgsw_hcmpcipher_small[0],
    );
    let lt_cipher_2 = param_data.rotationkey.lt_hcmp(
        &data.rlwe_hcmpcipher_great[0],
        &data.rgsw_hcmpcipher_great[0],
    );
    let lt_cipher_3 = param_data.rotationkey.lt_hcmp(
        &data.rlwe_hcmpcipher_small[0],
        &data.rgsw_hcmpcipher_great[0],
    );
    let lt_value_1 = decrypt(rlwe_sk, lt_cipher_1);
    let lt_value_2 = decrypt(rlwe_sk, lt_cipher_2);
    let lt_value_3 = decrypt(rlwe_sk, lt_cipher_3);
    assert_eq!(lt_value_1, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_2, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_3, 1);
}

#[test]
#[ignore = "slow"]
fn test_homand() {
    init_param();
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let sampler = param_data.param.ring_noise_distribution();
    let mut rng = thread_rng();

    let lwe_delta_0 = lwe_generate(rlwe_sk, sampler, &mut rng, DELTA);
    let lwe_delta_1 = lwe_generate(rlwe_sk, sampler, &mut rng, DELTA);
    let lwe_delta_neg_0 = lwe_generate_neg(rlwe_sk, sampler, &mut rng, DELTA);
    let lwe_delta_neg_1 = lwe_generate_neg(rlwe_sk, sampler, &mut rng, DELTA);

    let homand_cipher1 = param_data.rotationkey.homand(&lwe_delta_0, &lwe_delta_1);
    let homand_cipher2 = param_data
        .rotationkey
        .homand(&lwe_delta_0, &lwe_delta_neg_0);
    let homand_cipher3 = param_data
        .rotationkey
        .homand(&lwe_delta_neg_0, &lwe_delta_neg_1);
    let homand_cipher4 = param_data
        .rotationkey
        .homand(&lwe_delta_neg_0, &lwe_delta_neg_0);

    let output1 = decrypt(rlwe_sk, homand_cipher1);
    let output2 = decrypt(rlwe_sk, homand_cipher2);
    let output3 = decrypt(rlwe_sk, homand_cipher3);
    let output4 = decrypt(rlwe_sk, homand_cipher4);
    assert_eq!(output1, 1);
    assert_eq!(output2, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(output3, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(output4, param_data.param.lwe_plain_modulus() - 1);
}

#[test]
#[ignore = "slow"]
fn test_gt_arbhcmp() {
    init_param();
    init_cipher();
    let data = unsafe { INSTANCE_CIPHER.get().unwrap() };
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let gt_cipher_1 = param_data.rotationkey.gt_arbhcmp(
        &data.rlwe_arbhcmpcipher_great,
        &data.rgsw_arbhcmpcipher_small,
    );
    let gt_cipher_2 = param_data.rotationkey.gt_arbhcmp(
        &data.rlwe_arbhcmpcipher_great,
        &data.rgsw_arbhcmpcipher_great,
    );
    let gt_cipher_3 = param_data.rotationkey.gt_arbhcmp(
        &data.rlwe_arbhcmpcipher_small,
        &data.rgsw_arbhcmpcipher_great,
    );
    let gt_value_1 = decrypt(rlwe_sk, gt_cipher_1);
    let gt_value_2 = decrypt(rlwe_sk, gt_cipher_2);
    let gt_value_3 = decrypt(rlwe_sk, gt_cipher_3);
    assert_eq!(gt_value_1, 1);
    assert_eq!(gt_value_2, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(gt_value_3, param_data.param.lwe_plain_modulus() - 1);
}

#[test]
#[ignore = "slow"]
fn test_eq_arbhcmp() {
    init_param();
    init_cipher();
    let data = unsafe { INSTANCE_CIPHER.get().unwrap() };
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let eq_cipher_1 = param_data.rotationkey.eq_arbhcmp(
        &data.rlwe_arbhcmpcipher_great,
        &data.rgsw_arbhcmpcipher_small,
    );
    let eq_cipher_2 = param_data.rotationkey.eq_arbhcmp(
        &data.rlwe_arbhcmpcipher_great,
        &data.rgsw_arbhcmpcipher_great,
    );
    let eq_cipher_3 = param_data.rotationkey.eq_arbhcmp(
        &data.rlwe_arbhcmpcipher_small,
        &data.rgsw_arbhcmpcipher_great,
    );
    let eq_value_1 = decrypt(rlwe_sk, eq_cipher_1);
    let eq_value_2 = decrypt(rlwe_sk, eq_cipher_2);
    let eq_value_3 = decrypt(rlwe_sk, eq_cipher_3);
    assert_eq!(eq_value_1, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(eq_value_2, 1);
    assert_eq!(eq_value_3, param_data.param.lwe_plain_modulus() - 1);
}

#[test]
#[ignore = "slow"]
fn test_lt_arbhcmp() {
    init_param();
    init_cipher();
    let data = unsafe { INSTANCE_CIPHER.get().unwrap() };
    let param_data = unsafe { INSTANCE_PARAM.get().unwrap() };
    let rlwe_sk = param_data.sk.ring_secret_key().as_slice();
    let lt_cipher_1 = param_data.rotationkey.lt_arbhcmp(
        &data.rlwe_arbhcmpcipher_great,
        &data.rgsw_arbhcmpcipher_small,
    );
    let lt_cipher_2 = param_data.rotationkey.lt_arbhcmp(
        &data.rlwe_arbhcmpcipher_great,
        &data.rgsw_arbhcmpcipher_great,
    );
    let lt_cipher_3 = param_data.rotationkey.lt_arbhcmp(
        &data.rlwe_arbhcmpcipher_small,
        &data.rgsw_arbhcmpcipher_great,
    );
    let lt_value_1 = decrypt(rlwe_sk, lt_cipher_1);
    let lt_value_2 = decrypt(rlwe_sk, lt_cipher_2);
    let lt_value_3 = decrypt(rlwe_sk, lt_cipher_3);
    assert_eq!(lt_value_1, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_2, param_data.param.lwe_plain_modulus() - 1);
    assert_eq!(lt_value_3, 1);
}

fn lwe_generate<F, R>(
    secret_key: &[F],
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
    delta: F,
) -> LWE<F>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let rlwe_dimension = secret_key.len();
    let a = Polynomial::random(rlwe_dimension, &mut rng);
    let a_mul_s = a
        .iter()
        .zip(secret_key)
        .fold(F::zero(), |acc, (&s, &a)| acc.add_mul(s, a));
    let e: F = error_sampler.sample(&mut rng);
    let b = a_mul_s + delta + e;
    LWE::new(a.data(), b)
}

fn lwe_generate_neg<F, R>(
    secret_key: &[F],
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
    delta: F,
) -> LWE<F>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let rlwe_dimension = secret_key.len();
    let a = Polynomial::random(rlwe_dimension, &mut rng);
    let a_mul_s = a
        .iter()
        .zip(secret_key)
        .fold(F::zero(), |acc, (&s, &a)| acc.add_mul(s, a));
    let e: F = error_sampler.sample(&mut rng);
    let b = a_mul_s - delta + e;
    LWE::new(a.data(), b)
}
