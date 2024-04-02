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

    for i in 1..=10 {
        // and
        let m0 = rng.gen();
        let c0 = skp.encrypt(m0);

        let m1 = rng.gen();
        let c1 = skp.encrypt(m1);

        let c2 = evk.and(&c0, &c1);

        let (m2, noise) = skp.decrypt_with_noise(&c2);

        assert_eq!(m2, and(m0, m1), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // or
        let m3 = rng.gen();
        let c3 = skp.encrypt(m3);

        let c4 = evk.or(&c2, &c3);

        let (m4, noise) = skp.decrypt_with_noise(&c4);

        assert_eq!(m4, or(m2, m3), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // nor
        let m5 = rng.gen();
        let c5 = skp.encrypt(m5);

        let c6 = evk.nor(&c4, &c5);

        let (m6, noise) = skp.decrypt_with_noise(&c6);

        assert_eq!(m6, nor(m4, m5), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // xor
        let m7 = rng.gen();
        let c7 = skp.encrypt(m7);

        let c8 = evk.xor(&c6, &c7);

        let (m8, noise) = skp.decrypt_with_noise(&c8);

        assert_eq!(m8, xor(m6, m7), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // xnor
        let m9 = rng.gen();
        let c9 = skp.encrypt(m9);

        let c10 = evk.xnor(&c8, &c9);

        let (m10, noise) = skp.decrypt_with_noise(&c10);

        assert_eq!(m10, xnor(m8, m9), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // nand
        let m11 = rng.gen();
        let c11 = skp.encrypt(m11);

        let c12 = evk.nand(&c10, &c11);

        let (m12, noise) = skp.decrypt_with_noise(&c12);

        assert_eq!(m12, nand(m10, m11), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        // not
        let c13 = evk.not(&c12);

        let (m13, noise) = skp.decrypt_with_noise(&c13);

        assert_eq!(m13, not(m12), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        //majority
        let m14 = rng.gen();
        let c14 = skp.encrypt(m14);

        c = evk.majority(&c13, &c14, &c);

        let (d, noise) = skp.decrypt_with_noise(&c);

        assert_eq!(d, majority(m13, m14, m), "Noise: {noise}");
        assert!(noise < noise_max, "Noise: {noise} >= {noise_max}");
        println!("Noise: {noise} < {noise_max}");

        m = d;
        println!("The {i} group test done!\n");
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

#[inline]
fn or(a: bool, b: bool) -> bool {
    a | b
}

#[inline]
fn nor(a: bool, b: bool) -> bool {
    not(or(a, b))
}

#[inline]
fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

#[inline]
fn xnor(a: bool, b: bool) -> bool {
    not(xor(a, b))
}

#[inline]
fn majority(a: bool, b: bool, c: bool) -> bool {
    (a & b) | (b & c) | (a & c)
}
