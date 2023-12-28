use algebra::derive::*;

use vfhe::{LWEParam, LWESecretKeyDistribution, RingParam, Vfhe};

#[derive(Ring, Random)]
#[modulus = 1024]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073707009]
pub struct FF(u32);

fn main() {
    // set random generator
    // use rand::SeedableRng;
    // let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(11);
    let mut rng = rand::thread_rng();

    // set parameter
    let lwe = <LWEParam<RR>>::new(512, 4, 3.20, LWESecretKeyDistribution::Ternary);
    let rlwe = <RingParam<FF>>::new(1024, 2, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe, rlwe);

    // generate keys
    let sk = vfhe.generate_lwe_sk(&mut rng);
    let pk = vfhe.generate_lwe_pk(&sk, &mut rng);
    let rlwe_sk = vfhe.rlwe().generate_sk(&mut rng);
    let rlwe_pk = vfhe.rlwe().generate_pk(&rlwe_sk, &mut rng);
    let ksk = vfhe.generate_key_switching_key(&rlwe_sk, &sk, &mut rng);
    let bks = vfhe.generate_bootstrapping_key(&sk, &rlwe_sk, &mut rng);

    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);
    vfhe.rlwe_mut().set_secret_key(Some(rlwe_sk));
    vfhe.rlwe_mut().set_public_key(rlwe_pk);
    vfhe.set_key_switching_key(ksk);
    vfhe.set_bootstrapping_key(bks);

    let v = 1;
    let m = vfhe.encode(v);
    let c = vfhe.encrypt_by_pk(m, &mut rng);
    let m_d = vfhe.decrypt(&c);
    let v_d = vfhe.decode(m_d);

    assert_eq!(v, v_d);

    let v1 = 0;
    let m1 = vfhe.encode(v1);
    let c1 = vfhe.encrypt_by_pk(m1, &mut rng);
    let c2 = c.clone().add_component_wise(&c1);
    let m_2 = vfhe.decrypt(&c2);
    let v_2 = vfhe.decode(m_2);
    assert_eq!(v_2, (v + v1) % 4);

    let nand = vfhe.nand(c, &c1);

    // {
    // use lattice::dot_product;
    // use num_bigint::BigUint;
    // use num_traits::{ToPrimitive, Zero};
    //     let sk: Vec<FF> = vfhe
    //         .secret_key()
    //         .unwrap()
    //         .iter()
    //         .map(|&v| FF::from_f64(v.as_f64()))
    //         .collect();
    //     let r = nand.b() - dot_product(nand.a(), &sk);
    //     let r = RR::from_f64((r.as_f64() * vfhe.ql() / vfhe.qr()).round());
    //     dbg!(r);
    //     let dec = vfhe.decode(r);
    //     dbg!(dec);

    //     let encode = vfhe.encode(dec);
    //     let e = encode - r;
    //     dbg!(e);

    //     let right = BigUint::from(r.inner())
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
    // }

    let nand = nand.modulus_switch(vfhe.ql(), vfhe.qr());

    let m_3 = vfhe.decrypt(&nand);
    // dbg!(m_3);

    let v_3 = vfhe.decode(m_3);
    let rhs = 1 - v * v1;
    assert_eq!(v_3, rhs);
}
