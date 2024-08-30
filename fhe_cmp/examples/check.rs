use fhe_cmp::{
    compare::{decrypt, encrypt, HomCmpScheme},
    parameters::{DEFAULT_PARAMERTERS, DELTA, FF, HALF_DELTA},
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;
use std::{cmp::Ordering, time::Instant};
fn main() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let poly_length = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    
    //test hcmp
    println!("test hcmp");
    let x = rng.gen_range(0..1024);
    let y = rng.gen_range(0..1024);
    let (value1, value2) = encrypt(
        x,
        y,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let gt_cipher = rotationkey.gt_hcmp(&value1[0], &value2[0]);
    let eq_cipher = rotationkey.eq_hcmp(&value1[0], &value2[0]);
    let lt_cipher = rotationkey.lt_hcmp(&value1[0], &value2[0]);
    let gt_value = decrypt(rlwe_sk, gt_cipher);
    let eq_value = decrypt(rlwe_sk, eq_cipher);
    let lt_value = decrypt(rlwe_sk, lt_cipher);
    match x.cmp(&y) {
        Ordering::Less =>
        {
            assert_eq!(gt_value, 1);
            assert_eq!(eq_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Equal =>
        {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(eq_value, 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Greater =>
        {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, 1);
        }
        _ => {} // No error, do nothing
    }

    //test arbhcmp
    println!("test arbhcmp");
    let x = rng.gen_range(0..1024);
    let y = rng.gen_range(0..1024);
    let (value1, value2) = encrypt(
        x,
        y,
        sk.ntt_ring_secret_key(),
        basis,
        DELTA,
        sampler,
        &mut rng,
    );
    let gt_cipher = rotationkey.gt_hcmp(&value1[0], &value2[0]);
    let eq_cipher = rotationkey.eq_hcmp(&value1[0], &value2[0]);
    let lt_cipher = rotationkey.lt_hcmp(&value1[0], &value2[0]);
    let gt_value = decrypt(rlwe_sk, gt_cipher);
    let eq_value = decrypt(rlwe_sk, eq_cipher);
    let lt_value = decrypt(rlwe_sk, lt_cipher);
    match x.cmp(&y) {
        Ordering::Less =>
        {
            assert_eq!(gt_value, 1);
            assert_eq!(eq_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Equal =>
        {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(eq_value, 1);
            assert_eq!(lt_value, param.lwe_plain_modulus() - 1);
        }
        Ordering::Greater =>
        {
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(gt_value, param.lwe_plain_modulus() - 1);
            assert_eq!(lt_value, 1);
        }
        _ => {} // No error, do nothing
    }

}