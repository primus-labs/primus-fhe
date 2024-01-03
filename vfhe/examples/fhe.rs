use algebra::derive::*;
use vfhe::{LWEParam, LWESecretKeyDistribution, RingParam, Vfhe};

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
    let lwe = <LWEParam<RR>>::new(512, 4, 3.20, LWESecretKeyDistribution::Ternary);
    let rlwe = <RingParam<FF>>::new(1024, 5, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe, rlwe, 5);

    // generate keys
    let sk = vfhe.generate_lwe_sk(&mut rng);
    let pk = vfhe.generate_lwe_pk(&sk, &mut rng);
    let rlwe_sk = vfhe.generate_rlwe_sk(&mut rng);
    let rlwe_sk_ntt = rlwe_sk.clone().to_ntt_polynomial();
    let rlwe_pk = vfhe.generate_rlwe_pk(&rlwe_sk_ntt, &mut rng);
    let ksk = vfhe.generate_key_switching_key(&rlwe_sk, &sk, &mut rng);
    let bks = vfhe.generate_bootstrapping_key(&sk, &rlwe_sk_ntt, &mut rng);

    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);
    vfhe.rlwe_mut().set_secret_key(Some((rlwe_sk, rlwe_sk_ntt)));
    vfhe.rlwe_mut().set_public_key(rlwe_pk);
    vfhe.set_key_switching_key(ksk);
    vfhe.set_bootstrapping_key(bks);

    for i in 0..100 {
        println!("\n{i}\n");
        let v0 = if rand::random() { 1 } else { 0 };
        let m = vfhe.encode(v0);
        let c = vfhe.encrypt_by_pk(m, &mut rng);

        let v1 = if rand::random() { 1 } else { 0 };
        let m1 = vfhe.encode(v1);
        let c1 = vfhe.encrypt_by_pk(m1, &mut rng);

        let nand = vfhe.nand(c, &c1);

        let nand_round = nand.modulus_switch_round(vfhe.ql(), vfhe.qr());

        let m_3 = vfhe.decrypt(&nand_round);

        let v_3 = vfhe.decode(m_3);
        assert_eq!(v_3, nand_u32(v0, v1));

        let nand_floor = nand.modulus_switch_floor(vfhe.ql(), vfhe.qr());

        let m_3 = vfhe.decrypt(&nand_floor);

        let v_3 = vfhe.decode(m_3);
        assert_eq!(v_3, nand_u32(v0, v1));
    }
}

fn nand_u32(a: u32, b: u32) -> u32 {
    1 - a * b
}
