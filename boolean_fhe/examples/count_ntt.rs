use algebra::transformation::count;
use boolean_fhe::{EvaluationKey, LWEType, SecretKeyPack, DEFAULT_TERNARY_128_BITS_PARAMERTERS};
use rand::Rng;

fn main() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = DEFAULT_TERNARY_128_BITS_PARAMERTERS.clone();

    let noise_max = (params.lwe_modulus_f64() / 16.0) as LWEType;

    let check_noise = |noise: LWEType, op: &str| {
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

    let a = rng.gen();
    let b = rng.gen();
    let c = rng.gen();

    let x = skp.encrypt(a);
    let y = skp.encrypt(b);
    let z = skp.encrypt(c);

    count::enable_count_ntt_and_intt();
    let ct = evk.nand(&x, &y);
    count::disable_count_ntt_and_intt();

    let (m, noise) = skp.decrypt_with_noise(&ct);
    assert_eq!(m, nand(a, b), "Noise: {noise}");
    check_noise(noise, "nand");
    println!("ntt count: {}", count::get_ntt_count());
    println!("intt count: {}", count::get_intt_count());

    count::clear_ntt_count();
    count::clear_intt_count();

    count::enable_count_ntt_and_intt();
    let ct = evk.mux(&x, &y, &z);
    count::disable_count_ntt_and_intt();

    let (m, noise) = skp.decrypt_with_noise(&ct);
    assert_eq!(m, if a { b } else { c }, "Noise: {noise}");
    check_noise(noise, "mux");
    println!("ntt count: {}", count::get_ntt_count());
    println!("intt count: {}", count::get_intt_count());
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

#[allow(dead_code)]
#[inline]
fn or(a: bool, b: bool) -> bool {
    a | b
}

#[allow(dead_code)]
#[inline]
fn nor(a: bool, b: bool) -> bool {
    not(or(a, b))
}

#[allow(dead_code)]
#[inline]
fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

#[allow(dead_code)]
#[inline]
fn xnor(a: bool, b: bool) -> bool {
    not(xor(a, b))
}

#[allow(dead_code)]
#[inline]
fn majority(a: bool, b: bool, c: bool) -> bool {
    (a & b) | (b & c) | (a & c)
}
