use algebra::{FieldDiscreteGaussianSampler, NTTField, Polynomial};
use fhe_cmp::{
    compare::{decrypt, Encryptor, HomomorphicCmpScheme},
    parameters::DEFAULT_PARAMETERS,
};
use fhe_core::SecretKeyPack;
use lattice::LWE;
use rand::prelude::*;
use std::cmp::Ordering;

fn main() {
    let mut rng = thread_rng();

    let param = *DEFAULT_PARAMETERS;

    let neg_one = param.lwe_plain_modulus() - 1;

    let skp = SecretKeyPack::new(param);
    let rlwe_sk = skp.ring_secret_key().as_slice();
    let rotationkey = HomomorphicCmpScheme::new(&skp);
    let sampler = param.ring_noise_distribution();

    let encryptor = Encryptor::new(&skp);

    let x = rng.gen();
    let y = rng.gen();
    let x_hcmp = rng.gen_range(0..1024);
    let y_hcmp = rng.gen_range(0..1024);

    let mut value1 = encryptor.rlwe_encrypt(x, &mut rng);
    let mut value2 = encryptor.rgsw_encrypt(y, &mut rng);
    encryptor.align(&mut value1, &mut value2, &mut rng);

    let value1_hcmp = encryptor.rlwe_encrypt(x_hcmp, &mut rng);
    let value2_hcmp = encryptor.rgsw_encrypt(y_hcmp, &mut rng);

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
            assert_eq!(eq_value, neg_one);
            assert_eq!(lt_value, neg_one);
        }
        Ordering::Equal => {
            assert_eq!(gt_value, neg_one);
            assert_eq!(eq_value, 1);
            assert_eq!(lt_value, neg_one);
        }
        Ordering::Less => {
            assert_eq!(gt_value, neg_one);
            assert_eq!(gt_value, neg_one);
            assert_eq!(lt_value, 1);
        }
    }
    println!("finish hcmp test");

    //test arbhcmp
    println!("test arbhcmp");
    let gt_cipher = rotationkey.gt_arbhcmp(&value1, &value2);
    let eq_cipher = rotationkey.eq_arbhcmp(&value1, &value2);
    let lt_cipher = rotationkey.lt_arbhcmp(&value1, &value2);
    let gt_value = decrypt(rlwe_sk, gt_cipher);
    let eq_value = decrypt(rlwe_sk, eq_cipher);
    let lt_value = decrypt(rlwe_sk, lt_cipher);
    match x.cmp(&y) {
        Ordering::Greater => {
            assert_eq!(gt_value, 1);
            assert_eq!(eq_value, neg_one);
            assert_eq!(lt_value, neg_one);
        }
        Ordering::Equal => {
            assert_eq!(gt_value, neg_one);
            assert_eq!(eq_value, 1);
            assert_eq!(lt_value, neg_one);
        }
        Ordering::Less => {
            assert_eq!(gt_value, neg_one);
            assert_eq!(gt_value, neg_one);
            assert_eq!(lt_value, 1);
        }
    }
    println!("finish arbhcmp test");

    let delta = rotationkey.delta();

    //test homand only when 2 delta comes out delta
    println!("test homand");
    let lwe_delta = lwe_generate(rlwe_sk, sampler, &mut rng, delta);
    let lwe_delta_neg = lwe_generate_neg(rlwe_sk, sampler, &mut rng, delta);
    let homand_cipher1 = rotationkey.homand(&lwe_delta, &lwe_delta);
    let homand_cipher2 = rotationkey.homand(&lwe_delta, &lwe_delta_neg);
    let homand_cipher3 = rotationkey.homand(&lwe_delta_neg, &lwe_delta);
    let homand_cipher4 = rotationkey.homand(&lwe_delta_neg, &lwe_delta_neg);
    let output1 = decrypt(rlwe_sk, homand_cipher1);
    let output2 = decrypt(rlwe_sk, homand_cipher2);
    let output3 = decrypt(rlwe_sk, homand_cipher3);
    let output4 = decrypt(rlwe_sk, homand_cipher4);
    assert_eq!(output1, 1);
    assert_eq!(output2, neg_one);
    assert_eq!(output3, neg_one);
    assert_eq!(output4, neg_one);
    println!("finish homand test");
}

///generate LWE ciphertext which encrypts 1
pub fn lwe_generate<F, R>(
    secret_key: &[F],
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
    delta: F,
) -> LWE<F>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let a = Polynomial::random(secret_key.len(), &mut rng);
    let a_mul_s = a
        .iter()
        .zip(secret_key)
        .fold(F::zero(), |acc, (&a, &s)| acc.add_mul(a, s));
    let e: F = error_sampler.sample(&mut rng);
    let b = a_mul_s + delta + e;
    LWE::new(a.data(), b)
}

///generate LWE ciphertext which encrypts -1
pub fn lwe_generate_neg<F, R>(
    secret_key: &[F],
    error_sampler: FieldDiscreteGaussianSampler,
    mut rng: R,
    delta: F,
) -> LWE<F>
where
    R: Rng + CryptoRng,
    F: NTTField,
{
    let a = Polynomial::random(secret_key.len(), &mut rng);
    let a_mul_s = a
        .iter()
        .zip(secret_key)
        .fold(F::zero(), |acc, (&a, &s)| acc.add_mul(a, s));
    let e: F = error_sampler.sample(&mut rng);
    let b = a_mul_s - delta + e;
    LWE::new(a.data(), b)
}
