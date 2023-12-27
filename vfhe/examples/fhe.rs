use algebra::derive::*;
use vfhe::{LWEParam, LWESecretKeyDistribution, RingParam, Vfhe};

fn main() {
    let mut rng = rand::thread_rng();

    let lwe_param = <LWEParam<RR>>::new(512, 4, 3.20, LWESecretKeyDistribution::Binary);
    let rlwe_param = <RingParam<FF>>::new(1024, 2, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe_param, rlwe_param);

    let sk = vfhe.generate_lwe_sk(&mut rng);
    let pk = vfhe.generate_lwe_pk(&sk, &mut rng);
    let rlwe_sk = vfhe.rlwe().generate_sk(&mut rng);
    let rlwe_pk = vfhe.rlwe().generate_pk(&rlwe_sk, &mut rng);
    let ksk = vfhe.generate_key_switching_key(&rlwe_sk, &sk, &mut rng);

    assert_eq!(ksk.len(), 2);

    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);
    vfhe.rlwe_mut().set_secret_key(Some(rlwe_sk));
    vfhe.rlwe_mut().set_public_key(rlwe_pk);
    vfhe.set_ksk(ksk);

    let bks = vfhe.generate_bootstrapping_key();
    vfhe.set_bks(bks);

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

    // vfhe.set_secret_key(None);
    // vfhe.rlwe_mut().set_secret_key(None);

    let nand = vfhe.nand(c, &c1);

    // assert!(nand.a().iter().all(|&v| v.inner() < RR::modulus()));
    // assert!(nand.b().inner() < RR::modulus());

    let m_3 = vfhe.decrypt(&nand);
    dbg!(m_3);

    let v_3 = vfhe.decode(m_3);
    let rhs = dbg!(1 - v * v1);
    assert_eq!(v_3, rhs);
}

#[derive(Ring, Random)]
#[modulus = 512]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073707009]
pub struct FF(u32);
