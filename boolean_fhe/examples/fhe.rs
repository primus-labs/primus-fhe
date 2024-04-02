use boolean_fhe::{EvaluationKey, LWEType, SecretKeyPack, DEFAULT_TERNARY_128_BITS_PARAMERTERS};
use rand::Rng;

fn main() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_TERNARY_128_BITS_PARAMERTERS.clone();

    let noise_max = (params.lwe_modulus_f64() / 16.0) as LWEType;

    // generate keys
    let skp = SecretKeyPack::new(params);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp);
    println!("Evaluation Key Generation done!\n");

    let mut m = rng.gen();
    let mut c = skp.encrypt(m);

    for i in 1..=50 {
        // and
        let m0 = rng.gen();
        let c0 = skp.encrypt(m0);

        let m1 = rng.gen();
        let c1 = skp.encrypt(m1);

        let c2 = evk.and(&c0, &c1);

        let (m2, noise) = skp.decrypt_with_noise(&c2);

        assert_eq!(m2, m0 & m1, "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // or
        let m3 = rng.gen();
        let c3 = skp.encrypt(m3);

        let c4 = evk.or(&c2, &c3);

        let (m4, noise) = skp.decrypt_with_noise(&c4);

        assert_eq!(m4, m2 | m3, "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        assert_eq!(m2, m0 & m1, "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // nor
        let m5 = rng.gen();
        let c5 = skp.encrypt(m5);

        let c6 = evk.nor(&c4, &c5);

        let (m6, noise) = skp.decrypt_with_noise(&c6);

        assert_eq!(m6, !(m4 | m5), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // xor
        let m7 = rng.gen();
        let c7 = skp.encrypt(m7);

        let c8 = evk.xor(&c6, &c7);

        let (m8, noise) = skp.decrypt_with_noise(&c8);

        assert_eq!(m8, m6 ^ m7, "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // xnor
        let m9 = rng.gen();
        let c9 = skp.encrypt(m9);

        let c10 = evk.xnor(&c8, &c9);

        let (m10, noise) = skp.decrypt_with_noise(&c10);

        assert_eq!(m10, !(m8 ^ m9), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // nand
        c = evk.nand(&c, &c10);

        let (d, noise) = skp.decrypt_with_noise(&c);

        assert_eq!(d, !(m & m10), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");
        m = d;

        // not
        let c11 = evk.not(&c);
        let (d, noise) = skp.decrypt_with_noise(&c11);

        assert_eq!(d, !m, "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        println!("The {i} nand test done!\n");
    }
}
