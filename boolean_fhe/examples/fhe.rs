use algebra::Ring;
use boolean_fhe::{DefaultRing100, EvaluationKey, SecretKeyPack, DEFAULT_100_BITS_PARAMERTERS};
use rand::Rng;

fn main() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_100_BITS_PARAMERTERS.clone();

    // generate keys
    let skp = SecretKeyPack::new(params);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp);
    println!("Evaluation Key Generation done!\n");

    let mut m = rng.gen();
    let mut c = skp.encrypt(m);

    let noise_max = DefaultRing100::MODULUS_F64 / 16.0;
    for i in 1..=50 {
        let m0 = rng.gen();
        let c0 = skp.encrypt(m0);

        let m1 = rng.gen();
        let c1 = skp.encrypt(m1);

        let c2 = evk.nand(&c0, &c1);

        let (m2, noise) = skp.decrypt_with_noise(&c2);
        let noise = noise.to_f64();

        assert_eq!(m2, !(m0 & m1), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        c = evk.nand(&c, &c2);

        let (d, noise) = skp.decrypt_with_noise(&c);
        let noise = noise.to_f64();

        assert_eq!(d, !(m & m2), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        m = d;
        println!("The {i} nand test done!\n");
    }
}
