use algebra::NTTField;
use fhe_core::{utils::*, LWECiphertext, LWEModulusType};
use rand::Rng;
use zkfhe::{
    bfhe::{Evaluator, DEFAULT_TERNARY_128_BITS_PARAMERTERS},
    Decryptor, Encryptor, KeyGen,
};

type M = bool;
type C = u16;

fn main() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = *DEFAULT_TERNARY_128_BITS_PARAMERTERS;

    let noise_max = (params.lwe_cipher_modulus_value() as f64 / 16.0) as C;

    let check_noise = |noise: C, op: &str| {
        assert!(
            noise < noise_max,
            "Type: {op}\nNoise: {noise} >= {noise_max}"
        );
        println!("{op:4.4} Noise: {noise:3} < {noise_max:3}");
    };

    // generate keys
    let sk = KeyGen::generate_secret_key(params);
    println!("Secret Key Generation done!\n");

    let enc = Encryptor::new(sk.clone());
    let eval = Evaluator::new(&sk);
    let dec = Decryptor::new(sk);
    println!("Evaluation Key Generation done!\n");

    let mut a = rng.gen();
    let mut b = rng.gen();
    let mut c = rng.gen();

    let mut x = enc.encrypt(a);
    let mut y = enc.encrypt(b);
    let mut z = enc.encrypt(c);

    for i in 1..10 {
        // not
        let ct_not = eval.not(&x);
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_not);
        assert_eq!(m, not(a), "Noise: {noise}");
        check_noise(noise, "not");

        // perform all other homomorphic bit operations
        let start = std::time::Instant::now();
        let (ct_and, ct_nand, ct_or, ct_nor, ct_xor, ct_xnor, ct_majority, ct_mux) =
            join_bit_opearions(&eval, &x, &y, &z);
        let duration = start.elapsed();
        println!("Time elapsed in join_bit_opearions() is: {:?}", duration);

        // majority
        let (ma, noise) = dec.decrypt_with_noise(&ct_majority);
        assert_eq!(ma, majority(a, b, c), "Noise: {noise}");
        check_noise(noise, "majority");

        // and
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_and);
        assert_eq!(m, and(a, b), "Noise: {noise}");
        check_noise(noise, "and");

        // nand
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_nand);
        assert_eq!(m, nand(a, b), "Noise: {noise}");
        check_noise(noise, "nand");

        // xor
        let (mx, noise) = dec.decrypt_with_noise::<M>(&ct_xor);
        assert_eq!(mx, xor(a, b), "Noise: {noise}");
        check_noise(noise, "xor");

        // xnor
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_xnor);
        assert_eq!(m, xnor(a, b), "Noise: {noise}");
        check_noise(noise, "xnor");

        // or
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_or);
        assert_eq!(m, or(a, b), "Noise: {noise}");
        check_noise(noise, "or");

        // nor
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_nor);
        assert_eq!(m, nor(a, b), "Noise: {noise}");
        check_noise(noise, "nor");

        // mux
        let (m, noise) = dec.decrypt_with_noise::<M>(&ct_mux);
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

#[allow(clippy::type_complexity)]
fn join_bit_opearions<T: LWEModulusType, F: NTTField, Qks: NTTField>(
    eval: &Evaluator<T, F, Qks>,
    x: &LWECiphertext<T>,
    y: &LWECiphertext<T>,
    z: &LWECiphertext<T>,
) -> (
    LWECiphertext<T>,
    LWECiphertext<T>,
    LWECiphertext<T>,
    LWECiphertext<T>,
    LWECiphertext<T>,
    LWECiphertext<T>,
    LWECiphertext<T>,
    LWECiphertext<T>,
) {
    let mut ct_and: Option<LWECiphertext<T>> = None;
    let mut ct_nand: Option<LWECiphertext<T>> = None;
    let mut ct_or: Option<LWECiphertext<T>> = None;
    let mut ct_nor: Option<LWECiphertext<T>> = None;
    let mut ct_xor: Option<LWECiphertext<T>> = None;
    let mut ct_xnor: Option<LWECiphertext<T>> = None;
    let mut ct_majority: Option<LWECiphertext<T>> = None;
    let mut ct_mux: Option<LWECiphertext<T>> = None;

    rayon::scope(|s| {
        s.spawn(|_| ct_and = Some(eval.and(x, y)));
        s.spawn(|_| ct_nand = Some(eval.nand(x, y)));
        s.spawn(|_| ct_or = Some(eval.or(x, y)));
        s.spawn(|_| ct_nor = Some(eval.nor(x, y)));
        s.spawn(|_| ct_xor = Some(eval.xor(x, y)));
        s.spawn(|_| ct_xnor = Some(eval.xnor(x, y)));
        s.spawn(|_| ct_majority = Some(eval.majority(x, y, z)));
        s.spawn(|_| ct_mux = Some(eval.mux(x, y, z)));
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
