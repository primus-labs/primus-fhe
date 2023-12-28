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
    let rlwe = <RingParam<FF>>::new(1024, 16, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe, rlwe);

    // generate keys
    let sk = vfhe.generate_lwe_sk(&mut rng);
    let pk = vfhe.generate_lwe_pk(&sk, &mut rng);
    let rlwe_sk = vfhe.rlwe().generate_sk(&mut rng);
    let rlwe_sk_ntt = rlwe_sk.clone().to_ntt_polynomial();
    let rlwe_pk = vfhe.rlwe().generate_pk(&rlwe_sk_ntt, &mut rng);
    let ksk = vfhe.generate_key_switching_key(&rlwe_sk, &sk, &mut rng);
    let bks = vfhe.generate_bootstrapping_key(&sk, &rlwe_sk_ntt, &mut rng);

    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);
    vfhe.rlwe_mut().set_secret_key(Some(rlwe_sk));
    vfhe.rlwe_mut().set_public_key(rlwe_pk);
    vfhe.set_key_switching_key(ksk);
    vfhe.set_bootstrapping_key(bks);

    for i in 0..100 {
        println!("\n###################____{i}\n");
        let v0 = if rand::random() { 1 } else { 0 };
        let m = vfhe.encode(v0);
        let c = vfhe.encrypt_by_pk(m, &mut rng);

        let v1 = if rand::random() { 1 } else { 0 };
        let m1 = vfhe.encode(v1);
        let c1 = vfhe.encrypt_by_pk(m1, &mut rng);

        let nand = vfhe.nand(c, &c1);

        // {
        //     use algebra::ring::Ring;
        //     use lattice::dot_product;
        //     use num_bigint::BigUint;
        //     use num_traits::One;
        //     use num_traits::{ToPrimitive, Zero};

        //     dbg!(v0);
        //     dbg!(v1);
        //     dbg!(nand_u32(v0, v1));

        //     let r_neg_one = -RR::one();
        //     let f_neg_one = -FF::one();
        //     let sk: Vec<FF> = vfhe
        //         .secret_key()
        //         .unwrap()
        //         .iter()
        //         .map(|&v| {
        //             if v.is_zero() {
        //                 FF::zero()
        //             } else if v.is_one() {
        //                 FF::one()
        //             } else if v == r_neg_one {
        //                 f_neg_one
        //             } else {
        //                 panic!()
        //             }
        //         })
        //         .collect();
        //     let r0 = nand.b() - dot_product(nand.a(), &sk);
        //     let r = RR::from_f64((r0.as_f64() * vfhe.ql() / vfhe.qr()).round());
        //     dbg!(r);
        //     let dec = vfhe.decode(r);
        //     dbg!(dec);

        //     let encode = vfhe.encode(dec);
        //     let e = encode - r;
        //     dbg!(e);

        //     let right = BigUint::from(r0.inner())
        //         + nand
        //             .a()
        //             .iter()
        //             .zip(sk.iter())
        //             .fold(BigUint::zero(), |acc, (a, s)| {
        //                 acc + BigUint::from(a.inner()) * BigUint::from(s.inner())
        //             });

        //     dbg!(right.clone());
        //     dbg!(nand.b().as_f64());
        //     let n = (right.clone().to_f64().unwrap() - nand.b().as_f64()) / vfhe.qr();
        //     dbg!(n);

        //     // let n = n.to_f64().unwrap();
        //     let left = (n * vfhe.qr() + nand.b().as_f64()) * vfhe.ql() / vfhe.qr();
        //     let right = right.to_f64().unwrap() * vfhe.ql() / vfhe.qr();

        //     assert_eq!(left, right);

        //     let left = n * vfhe.ql() + (nand.b().as_f64() * vfhe.ql() / vfhe.qr()).round();
        //     let righ = (r0.as_f64() * vfhe.ql() / vfhe.qr()).round()
        //         + nand.a().iter().zip(vfhe.secret_key().unwrap().iter()).fold(
        //             0.0,
        //             |acc, (a, s)| {
        //                 acc + (a.as_f64() * vfhe.ql() / vfhe.qr()).round()
        //                     * if s.is_zero() {
        //                         0.0
        //                     } else if s.is_one() {
        //                         1.0
        //                     } else if *s == r_neg_one {
        //                         -1.0
        //                     } else {
        //                         panic!()
        //                     }
        //             },
        //         );
        //     dbg!(left);
        //     dbg!(righ);
        //     dbg!((left - righ).abs());

        //     let left = n * vfhe.ql() + (nand.b().as_f64() * vfhe.ql() / vfhe.qr()).floor();
        //     let righ = (r0.as_f64() * vfhe.ql() / vfhe.qr()).floor()
        //         + nand.a().iter().zip(vfhe.secret_key().unwrap().iter()).fold(
        //             0.0,
        //             |acc, (a, s)| {
        //                 acc + (a.as_f64() * vfhe.ql() / vfhe.qr()).floor()
        //                     * if s.is_zero() {
        //                         0.0
        //                     } else if s.is_one() {
        //                         1.0
        //                     } else if *s == r_neg_one {
        //                         -1.0
        //                     } else {
        //                         panic!()
        //                     }
        //             },
        //         );
        //     dbg!(left);
        //     dbg!(righ);
        //     dbg!((left - righ).abs());
        // }

        let nand_round = nand.modulus_switch_round(vfhe.ql(), vfhe.qr());

        let m_3 = vfhe.decrypt(&nand_round);
        // dbg!(m_3);

        let v_3 = vfhe.decode(m_3);
        assert_eq!(v_3, nand_u32(v0, v1));

        let nand_floor = nand.modulus_switch_floor(vfhe.ql(), vfhe.qr());

        let m_3 = vfhe.decrypt(&nand_floor);
        // dbg!(m_3);

        let v_3 = vfhe.decode(m_3);
        assert_eq!(v_3, nand_u32(v0, v1));
    }
}

fn nand_u32(a: u32, b: u32) -> u32 {
    1 - a * b
}
