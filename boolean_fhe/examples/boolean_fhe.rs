use algebra::{integer::UnsignedInteger, modulus::PowOf2Modulus, reduce::RingReduce, NttField};
use boolean_fhe::{Decryptor, Encryptor, Evaluator, KeyGen, DEFAULT_128_BITS_PARAMETERS};
use fhe_core::{LweCiphertext, ModulusValue};
use rand::{distributions::Uniform, Rng};

type Msg = u8;
type C = u16;
fn main() {
    // set random generator
    let mut rng = rand::thread_rng();

    // set parameter
    let params = *DEFAULT_128_BITS_PARAMETERS;

    let noise_max = match params.lwe_cipher_modulus_value() {
        ModulusValue::Native => (2.0f64.powi(C::BITS as i32 - 2)) as C,
        ModulusValue::PowerOf2(q) | ModulusValue::Prime(q) | ModulusValue::Others(q) => {
            (q as f64 / 8.0) as C
        }
    };

    let check_noise = |noise: C, op: &str| {
        assert!(
            noise < noise_max,
            "Type: {op}\nNoise: {noise} >= {noise_max}"
        );
        println!("{op:4.4} Noise: {noise:3} < {noise_max:3}");
    };

    let modulus = <PowOf2Modulus<C>>::new_with_mask(params.lwe_cipher_modulus_minus_one());

    // generate keys
    let sk = KeyGen::generate_secret_key(params, &mut rng);
    println!("Secret Key Generation done!\n");

    let enc = Encryptor::new(&sk);
    let dec = Decryptor::new(&sk);
    let eval = Evaluator::new(&sk, modulus, &mut rng);
    println!("Evaluation Key Generation done!\n");

    let distr = Uniform::new_inclusive(0, 1);

    let mut a: Msg = rng.sample(distr);
    let mut b: Msg = rng.sample(distr);
    let mut c: Msg = rng.sample(distr);

    let mut x = enc.encrypt(a, modulus, &mut rng);
    let mut y = enc.encrypt(b, modulus, &mut rng);
    let mut z = enc.encrypt(c, modulus, &mut rng);

    for i in 1..20 {
        // not
        let ct_not = eval.not(&x, modulus);
        let (m, noise) = dec.decrypt_with_noise::<Msg>(&ct_not, modulus);
        assert_eq!(m, a ^ 1, "Noise: {noise}");
        check_noise(noise, "not");

        // perform all other homomorphic bit operations
        let start = std::time::Instant::now();
        let (ct_and, ct_nand, ct_or, ct_nor, ct_xor, ct_xnor, ct_majority) =
            join_bit_operations(&eval, &x, &y, &z, modulus);
        let duration = start.elapsed();
        println!("Time elapsed in join_bit_operations() is: {:?}", duration);

        // majority
        let (ma, noise) = dec.decrypt_with_noise::<Msg>(&ct_majority, modulus);
        assert_eq!(ma, (a & b) | (b & c) | (a & c), "Noise: {noise}");
        check_noise(noise, "majority");

        // and
        let (m, noise) = dec.decrypt_with_noise::<Msg>(&ct_and, modulus);
        assert_eq!(m, a & b, "Noise: {noise}");
        check_noise(noise, "and");

        // nand
        let (m, noise) = dec.decrypt_with_noise::<Msg>(&ct_nand, modulus);
        assert_eq!(m, (a & b) ^ 1, "Noise: {noise}");
        check_noise(noise, "nand");

        // xor
        let (mxor, noise) = dec.decrypt_with_noise::<Msg>(&ct_xor, modulus);
        assert_eq!(mxor, a ^ b, "Noise: {noise}");
        check_noise(noise, "xor");

        // xnor
        let (m, noise) = dec.decrypt_with_noise::<Msg>(&ct_xnor, modulus);
        assert_eq!(m, (a ^ b) ^ 1, "Noise: {noise}");
        check_noise(noise, "xnor");

        // or
        let (m, noise) = dec.decrypt_with_noise::<Msg>(&ct_or, modulus);
        assert_eq!(m, a | b, "Noise: {noise}");
        check_noise(noise, "or");

        // nor
        let (m, noise) = dec.decrypt_with_noise::<Msg>(&ct_nor, modulus);
        assert_eq!(m, (a | b) ^ 1, "Noise: {noise}");
        check_noise(noise, "nor");

        a = b;
        x = y;

        b = ma;
        y = ct_majority;

        c = mxor;
        z = ct_xor;

        println!("The {i} group test done!\n");
    }
}

#[allow(clippy::type_complexity)]
fn join_bit_operations<T: UnsignedInteger, F: NttField>(
    eval: &Evaluator<T, F>,
    x: &LweCiphertext<T>,
    y: &LweCiphertext<T>,
    z: &LweCiphertext<T>,
    cipher_modulus: impl RingReduce<T>,
) -> (
    LweCiphertext<T>,
    LweCiphertext<T>,
    LweCiphertext<T>,
    LweCiphertext<T>,
    LweCiphertext<T>,
    LweCiphertext<T>,
    LweCiphertext<T>,
) {
    let mut ct_and: Option<LweCiphertext<T>> = None;
    let mut ct_nand: Option<LweCiphertext<T>> = None;
    let mut ct_or: Option<LweCiphertext<T>> = None;
    let mut ct_nor: Option<LweCiphertext<T>> = None;
    let mut ct_xor: Option<LweCiphertext<T>> = None;
    let mut ct_xnor: Option<LweCiphertext<T>> = None;
    let mut ct_majority: Option<LweCiphertext<T>> = None;

    rayon::scope(|s| {
        s.spawn(|_| ct_and = Some(eval.and(x, y, cipher_modulus)));
        s.spawn(|_| ct_nand = Some(eval.nand(x, y, cipher_modulus)));
        s.spawn(|_| ct_or = Some(eval.or(x, y, cipher_modulus)));
        s.spawn(|_| ct_nor = Some(eval.nor(x, y, cipher_modulus)));
        s.spawn(|_| ct_xor = Some(eval.xor(x, y, cipher_modulus)));
        s.spawn(|_| ct_xnor = Some(eval.xnor(x, y, cipher_modulus)));
        s.spawn(|_| ct_majority = Some(eval.majority(x, y, z, cipher_modulus)));
    });
    (
        ct_and.unwrap(),
        ct_nand.unwrap(),
        ct_or.unwrap(),
        ct_nor.unwrap(),
        ct_xor.unwrap(),
        ct_xnor.unwrap(),
        ct_majority.unwrap(),
    )
}
