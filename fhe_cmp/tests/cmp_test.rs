use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial};
use fhe_cmp::{
    compare::{decrypt, Encryptor, HomomorphicCmpScheme},
    parameters::{DEFAULT_PARAMETERS, FF},
};
use fhe_core::{Parameters, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use once_cell::sync::OnceCell;
use rand::prelude::*;

struct InitializationDataParam {
    skp: SecretKeyPack<u64, FF>,
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

fn get_params() -> &'static InitializationDataParam {
    static mut INSTANCE_PARAM: OnceCell<InitializationDataParam> = OnceCell::new();

    unsafe {
        INSTANCE_PARAM.get_or_init(|| {
            let param = *DEFAULT_PARAMETERS;
            let skp = SecretKeyPack::new(param);
            let rotationkey = HomomorphicCmpScheme::new(&skp);
            InitializationDataParam {
                skp,
                rotationkey,
                param,
            }
        })
    }
}

fn get_ciphers() -> &'static InitializationDataCipher {
    static INSTANCE_CIPHER: OnceCell<InitializationDataCipher> = OnceCell::new();

    INSTANCE_CIPHER.get_or_init(|| {
        let param_data = get_params();

        let n = param_data.param.ring_dimension();

        let mut rng = thread_rng();

        let hcmp_great = rng.gen_range(1..n);
        let hcmp_small = rng.gen_range(0..hcmp_great);
        let arbhcmp_great = rng.gen_range(1..(n * n * n * n));
        let arbhcmp_small = rng.gen_range(0..arbhcmp_great);

        let encryptor = Encryptor::new(&param_data.skp);

        let value1_hcmp_great = encryptor.rlwe_encrypt(hcmp_great, &mut rng);
        let value1_hcmp_small = encryptor.rlwe_encrypt(hcmp_small, &mut rng);
        let value2_hcmp_great = encryptor.rgsw_encrypt(hcmp_great, &mut rng);
        let value2_hcmp_small = encryptor.rgsw_encrypt(hcmp_small, &mut rng);
        let value1_arbhcmp_great = encryptor.rlwe_encrypt(arbhcmp_great, &mut rng);
        let value1_arbhcmp_small = encryptor.rlwe_encrypt(arbhcmp_small, &mut rng);
        let value2_arbhcmp_great = encryptor.rgsw_encrypt(arbhcmp_great, &mut rng);
        let value2_arbhcmp_small = encryptor.rgsw_encrypt(arbhcmp_small, &mut rng);
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
    })
}

#[test]
#[ignore = "slow"]
fn test_gt_hcmp() {
    let param_data = get_params();
    let ciphers = get_ciphers();

    let gt_cipher_1 = param_data.rotationkey.gt_hcmp(
        &ciphers.rlwe_hcmpcipher_great[0],
        &ciphers.rgsw_hcmpcipher_small[0],
    );
    let gt_cipher_2 = param_data.rotationkey.gt_hcmp(
        &ciphers.rlwe_hcmpcipher_great[0],
        &ciphers.rgsw_hcmpcipher_great[0],
    );
    let gt_cipher_3 = param_data.rotationkey.gt_hcmp(
        &ciphers.rlwe_hcmpcipher_small[0],
        &ciphers.rgsw_hcmpcipher_great[0],
    );

    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
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
    let param_data = get_params();
    let ciphers = get_ciphers();

    let eq_cipher_1 = param_data.rotationkey.eq_hcmp(
        &ciphers.rlwe_hcmpcipher_great[0],
        &ciphers.rgsw_hcmpcipher_small[0],
    );
    let eq_cipher_2 = param_data.rotationkey.eq_hcmp(
        &ciphers.rlwe_hcmpcipher_great[0],
        &ciphers.rgsw_hcmpcipher_great[0],
    );
    let eq_cipher_3 = param_data.rotationkey.eq_hcmp(
        &ciphers.rlwe_hcmpcipher_small[0],
        &ciphers.rgsw_hcmpcipher_great[0],
    );

    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
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
    let param_data = get_params();
    let ciphers = get_ciphers();

    let lt_cipher_1 = param_data.rotationkey.lt_hcmp(
        &ciphers.rlwe_hcmpcipher_great[0],
        &ciphers.rgsw_hcmpcipher_small[0],
    );
    let lt_cipher_2 = param_data.rotationkey.lt_hcmp(
        &ciphers.rlwe_hcmpcipher_great[0],
        &ciphers.rgsw_hcmpcipher_great[0],
    );
    let lt_cipher_3 = param_data.rotationkey.lt_hcmp(
        &ciphers.rlwe_hcmpcipher_small[0],
        &ciphers.rgsw_hcmpcipher_great[0],
    );

    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
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
    let param_data = get_params();

    let delta = param_data.rotationkey.delta();
    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
    let sampler = param_data.param.ring_noise_distribution();
    let mut rng = thread_rng();

    let lwe_delta_0 = lwe_generate(rlwe_sk, sampler, &mut rng, delta);
    let lwe_delta_1 = lwe_generate(rlwe_sk, sampler, &mut rng, delta);
    let lwe_delta_neg_0 = lwe_generate_neg(rlwe_sk, sampler, &mut rng, delta);
    let lwe_delta_neg_1 = lwe_generate_neg(rlwe_sk, sampler, &mut rng, delta);

    let homand_cipher1 = param_data.rotationkey.homand(&lwe_delta_0, &lwe_delta_1);
    let homand_cipher2 = param_data
        .rotationkey
        .homand(&lwe_delta_0, &lwe_delta_neg_1);
    let homand_cipher3 = param_data
        .rotationkey
        .homand(&lwe_delta_neg_0, &lwe_delta_1);
    let homand_cipher4 = param_data
        .rotationkey
        .homand(&lwe_delta_neg_0, &lwe_delta_neg_1);

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
    let param_data = get_params();
    let ciphers = get_ciphers();

    let gt_cipher_1 = param_data.rotationkey.gt_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_great,
        &ciphers.rgsw_arbhcmpcipher_small,
    );
    let gt_cipher_2 = param_data.rotationkey.gt_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_great,
        &ciphers.rgsw_arbhcmpcipher_great,
    );
    let gt_cipher_3 = param_data.rotationkey.gt_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_small,
        &ciphers.rgsw_arbhcmpcipher_great,
    );

    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
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
    let param_data = get_params();
    let ciphers = get_ciphers();

    let eq_cipher_1 = param_data.rotationkey.eq_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_great,
        &ciphers.rgsw_arbhcmpcipher_small,
    );
    let eq_cipher_2 = param_data.rotationkey.eq_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_great,
        &ciphers.rgsw_arbhcmpcipher_great,
    );
    let eq_cipher_3 = param_data.rotationkey.eq_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_small,
        &ciphers.rgsw_arbhcmpcipher_great,
    );

    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
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
    let param_data = get_params();
    let ciphers = get_ciphers();

    let lt_cipher_1 = param_data.rotationkey.lt_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_great,
        &ciphers.rgsw_arbhcmpcipher_small,
    );
    let lt_cipher_2 = param_data.rotationkey.lt_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_great,
        &ciphers.rgsw_arbhcmpcipher_great,
    );
    let lt_cipher_3 = param_data.rotationkey.lt_arbhcmp(
        &ciphers.rlwe_arbhcmpcipher_small,
        &ciphers.rgsw_arbhcmpcipher_great,
    );

    let rlwe_sk = param_data.skp.ring_secret_key().as_slice();
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
