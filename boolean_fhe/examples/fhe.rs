use boolean_fhe::{EvaluationKey, SecretKeyPack, DEFAULT_100_BITS_PARAMERTERS};
use rand::Rng;

fn main() {
    // set random generator
    // use rand::SeedableRng;
    // let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11);
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

    for i in 0..100 {
        let m1 = rng.gen();
        let c1 = skp.encrypt(m1);

        c = evk.nand(&c1, &c);

        let d = skp.decrypt(&c);
        assert_eq!(d, !(m & m1));
        m = d;
        println!("The {i} nand test done!\n");
    }
}
