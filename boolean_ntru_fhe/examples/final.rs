use algebra::{reduce::SubReduce, Field};
use boolean_ntru_fhe::{
    decode, encode, DefaultFieldTernary128, EvaluationKey, LWEPlaintext, SecretKeyPack,
    DEFAULT_TERNARY_128_BITS_PARAMERTERS,
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

        let r = ct_nand.data() * skp.ntt_ring_secret_key();

        let r = r[0];

        let parameters = skp.parameters();
        let lwe_modulus_f64 = parameters.lwe_modulus_f64();
        let ntru_modulus_f64 = parameters.ntru_modulus_f64();

        let switch = |v: DefaultFieldTernary128| {
            (v.get() as f64 * lwe_modulus_f64 / ntru_modulus_f64).round() as LWEPlaintext
        };

        let lwe_modulus = parameters.lwe_modulus();
        let plaintext = switch(r);
        let message = decode(plaintext, lwe_modulus.value());

        let fresh = encode(message, lwe_modulus.value());

        let noise = plaintext
            .sub_reduce(fresh, lwe_modulus)
            .min(fresh.sub_reduce(plaintext, lwe_modulus));

        assert_eq!(message, c, "Noise: {noise}");
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
