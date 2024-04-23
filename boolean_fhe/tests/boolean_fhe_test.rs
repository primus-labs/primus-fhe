use algebra::NTTField;
use boolean_fhe::{
    EvaluationKey, LWECiphertext, LWEContainer, SecretKeyPack, DEFAULT_TERNARY_128_BITS_PARAMERTERS,
};
use rand::prelude::*;

#[test]
#[ignore = "run slowly in test mode, disable it for github action"]
fn bfhe_test() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_TERNARY_128_BITS_PARAMERTERS.clone();

    let noise_max = (params.lwe_modulus_f64() / 16.0) as LWEContainer;

    let check_noise = |noise: LWEContainer, op: &str| {
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

    let mut a = rng.gen();
    let mut b = rng.gen();
    let mut c = rng.gen();

    let mut x = skp.encrypt(a);
    let mut y = skp.encrypt(b);
    let mut z = skp.encrypt(c);

    for i in 1..5 {
        // not
        let ct_not = evk.not(&x);
        let (m, noise) = skp.decrypt_with_noise(&ct_not);
        assert_eq!(m, not(a), "Noise: {noise}");
        check_noise(noise, "not");

        // perform all other homomorphic bit operations
        let start = std::time::Instant::now();
        let (ct_and, ct_nand, ct_or, ct_nor, ct_xor, ct_xnor, ct_majority, ct_mux) =
            join_bit_opearions(&evk, &x, &y, &z);
        let duration = start.elapsed();
        println!("Time elapsed in join_bit_opearions() is: {:?}", duration);

        // majority
        let (ma, noise) = skp.decrypt_with_noise(&ct_majority);
        assert_eq!(ma, majority(a, b, c), "Noise: {noise}");
        check_noise(noise, "majority");

        // and
        let (m, noise) = skp.decrypt_with_noise(&ct_and);
        assert_eq!(m, and(a, b), "Noise: {noise}");
        check_noise(noise, "and");

        // nand
        let (m, noise) = skp.decrypt_with_noise(&ct_nand);
        assert_eq!(m, nand(a, b), "Noise: {noise}");
        check_noise(noise, "nand");

        // xor
        let (mx, noise) = skp.decrypt_with_noise(&ct_xor);
        assert_eq!(mx, xor(a, b), "Noise: {noise}");
        check_noise(noise, "xor");

        // xnor
        let (m, noise) = skp.decrypt_with_noise(&ct_xnor);
        assert_eq!(m, xnor(a, b), "Noise: {noise}");
        check_noise(noise, "xnor");

        // or
        let (m, noise) = skp.decrypt_with_noise(&ct_or);
        assert_eq!(m, or(a, b), "Noise: {noise}");
        check_noise(noise, "or");

        // nor
        let (m, noise) = skp.decrypt_with_noise(&ct_nor);
        assert_eq!(m, nor(a, b), "Noise: {noise}");
        check_noise(noise, "nor");

        // mux
        let (m, noise) = skp.decrypt_with_noise(&ct_mux);
        assert_eq!(m, if a { b } else { c }, "Noise: {noise}");
        check_noise(noise, "mux");

        a = m;
        x = ct_mux;

        b = ma;
        y = ct_majority;

        c = mx;
        z = ct_xor;

        println!("The {i} group test done!\n");
    }
}

fn join_bit_opearions<F: NTTField>(
    evk: &EvaluationKey<F>,
    x: &LWECiphertext,
    y: &LWECiphertext,
    z: &LWECiphertext,
) -> (
    LWECiphertext,
    LWECiphertext,
    LWECiphertext,
    LWECiphertext,
    LWECiphertext,
    LWECiphertext,
    LWECiphertext,
    LWECiphertext,
) {
    let mut ct_and: Option<LWECiphertext> = None;
    let mut ct_nand: Option<LWECiphertext> = None;
    let mut ct_or: Option<LWECiphertext> = None;
    let mut ct_nor: Option<LWECiphertext> = None;
    let mut ct_xor: Option<LWECiphertext> = None;
    let mut ct_xnor: Option<LWECiphertext> = None;
    let mut ct_majority: Option<LWECiphertext> = None;
    let mut ct_mux: Option<LWECiphertext> = None;

    rayon::scope(|s| {
        s.spawn(|_| ct_and = Some(evk.and(x, y)));
        s.spawn(|_| ct_nand = Some(evk.nand(x, y)));
        s.spawn(|_| ct_or = Some(evk.or(x, y)));
        s.spawn(|_| ct_nor = Some(evk.nor(x, y)));
        s.spawn(|_| ct_xor = Some(evk.xor(x, y)));
        s.spawn(|_| ct_xnor = Some(evk.xnor(x, y)));
        s.spawn(|_| ct_majority = Some(evk.majority(x, y, z)));
        s.spawn(|_| ct_mux = Some(evk.mux(x, y, z)));
    });
    (
        ct_and.unwrap(),
        ct_nand.unwrap(),
        ct_or.unwrap(),
        ct_nor.unwrap(),
        ct_xor.unwrap(),
        ct_xnor.unwrap(),
        ct_majority.unwrap(),
        ct_mux.unwrap(),
    )
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
