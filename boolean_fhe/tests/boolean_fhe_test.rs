use boolean_fhe::{EvaluationKey, LWEType, SecretKeyPack, DEFAULT_TERNARY_128_BITS_PARAMERTERS};
use rand::prelude::*;

#[test]
#[ignore = "run slowly in test mode, disable it for github action"]
fn test_nand() {
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_TERNARY_128_BITS_PARAMERTERS.clone();

    let noise_max = (params.lwe_modulus_f64() / 16.0) as LWEType;

    // generate keys
    let skp = SecretKeyPack::new(params);

    let evk = EvaluationKey::new(&skp);

    let mut m = rng.gen();
    let mut c = skp.encrypt(m);

    for i in 1..=50 {
        let m0 = rng.gen();
        let c0 = skp.encrypt(m0);

        let m1 = rng.gen();
        let c1 = skp.encrypt(m1);

        let c2 = evk.nand(&c0, &c1);

        let (m2, noise) = skp.decrypt_with_noise(&c2);

        assert_eq!(m2, !(m0 & m1), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        c = evk.nand(&c, &c2);

        let (d, noise) = skp.decrypt_with_noise(&c);

        assert_eq!(d, !(m & m2), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        m = d;
        println!("The {i} nand test done!\n");
    }
}
