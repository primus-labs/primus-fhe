use boolean_fhe::{EvaluationKey, LWEType, SecretKeyPack, DEFAULT_100_BITS_PARAMERTERS};
use rand::prelude::*;

#[test]
#[ignore = "run slowly in test mode, disable it for github action"]
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
    assert!(noise <= (DEFAULT_100_BITS_PARAMERTERS.lwe_modulus_f64() / 16.0) as LWEType);
}
