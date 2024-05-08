use boolean_ntru_fhe::{
    EvaluationKey, LWEPlaintext, SecretKeyPack, DEFAULT_TERNARY_128_BITS_PARAMERTERS,
};
use rand::Rng;

fn main() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_TERNARY_128_BITS_PARAMERTERS.clone();

    let noise_max = (params.lwe_modulus_f64() / 16.0) as LWEPlaintext;

    let check_noise = |noise: LWEPlaintext, op: &str| {
        assert!(
            noise < noise_max,
            "Type: {op}\nNoise: {noise} >= {noise_max}"
        );
        println!("{op:4.4} Noise: {noise:3} < {noise_max:3}");
    };

    // generate keys
    let skp = SecretKeyPack::new(params);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp);
    println!("Evaluation Key Generation done!\n");

    for _ in 0..10 {
        let a = rng.gen();
        let b = rng.gen();
        let c = nand(a, b);

        let x = skp.encrypt(a);
        let y = skp.encrypt(b);

        let ct_nand = evk.nand(&x, &y);

        let (m, noise) = skp.decrypt_with_noise(&ct_nand);

        assert_eq!(m, c, "Noise: {noise}");
        check_noise(noise, "nand");
    }
}

#[inline]
fn not(a: bool) -> bool {
    !a
}

#[inline]
fn and(a: bool, b: bool) -> bool {
    a & b
}

#[inline]
fn nand(a: bool, b: bool) -> bool {
    not(and(a, b))
}
