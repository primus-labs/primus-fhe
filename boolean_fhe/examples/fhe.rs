use algebra::derive::*;
use boolean_fhe::{EvaluationKey, Parameters, SecretKeyPack, SecretKeyType};
use rand::Rng;

#[derive(Ring, Random)]
#[modulus = 1024]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073692673]
pub struct FF(u32);

fn main() {
    // set random generator
    // use rand::SeedableRng;
    // let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11);
    let mut rng = rand::thread_rng();

    // set parameter
    let params = <Parameters<RR, FF>>::new(4, 512, 1024, SecretKeyType::Ternary, 6, 5, 3.2, 3.2);

    // generate keys
    let skp = SecretKeyPack::new(params, &mut rng);
    println!("Secret Key Generation done!\n");

    let evk = EvaluationKey::new(&skp, &mut rng);
    println!("Evaluation Key Generation done!\n");

    let mut m = rng.gen();
    let mut c = skp.encrypt(m, &mut rng);

    for i in 0..100 {
        let m1 = rng.gen();
        let c1 = skp.encrypt(m1, &mut rng);

        c = evk.nand(c1, &c);

        let d = skp.decrypt(&c);
        assert_eq!(d, !(m & m1));
        m = d;
        println!("The {i} nand test done!\n");
    }
}
