use algebra::Ring;
use boolean_fhe::{DefaultRing100, EvaluationKey, SecretKeyPack, DEFAULT_100_BITS_PARAMERTERS};
use rand::prelude::*;

#[test]
fn test_nand() {
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_100_BITS_PARAMERTERS.clone();

    // generate keys
    let skp = SecretKeyPack::new(params);

    let evk = EvaluationKey::new(&skp);

    // encrypt
    let m0 = rng.gen();
    let c0 = skp.encrypt(m0);

    let m1 = rng.gen();
    let c1 = skp.encrypt(m1);

    // nand
    let c2 = evk.nand(&c0, &c1);

    // decrypt
    let (m2, noise) = skp.decrypt_with_noise(&c2);

    // check
    assert_eq!(m2, !(m0 & m1));
    // println!(
    //     "Noise: {}",
    //     DefaultRing100::MODULUS_F64 / 16.0 - noise.as_f64()
    // );
    assert!(noise.as_f64() <= DefaultRing100::MODULUS_F64 / 16.0);
}
