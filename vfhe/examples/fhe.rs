use algebra::derive::*;
use vfhe::{LWEParam, LWESecretKeyDistribution, RingParam, Vfhe};

fn main() {
    let mut rng = rand::thread_rng();

    let lwe_param = <LWEParam<RR>>::new(512, 4, 512, 3.20, LWESecretKeyDistribution::Binary);
    let rlwe_param = <RingParam<FF>>::new(1024, 132120577, 4, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe_param, rlwe_param);

    let sk = vfhe.generate_lwe_sk(&mut rng);
    let pk = vfhe.generate_lwe_pk(&sk, &mut rng);
    vfhe.set_secret_key(Some(sk.clone()));
    vfhe.set_public_key(pk);

    let rlwe_sk = vfhe.rlwe().generate_sk(&mut rng);
    let rlwe_pk = vfhe.rlwe().generate_pk(&rlwe_sk, &mut rng);
    vfhe.rlwe_mut().set_secret_key(Some(rlwe_sk.clone()));
    vfhe.rlwe_mut().set_public_key(rlwe_pk);

    let v = 0;
    let m = vfhe.encode(v);
    let c = vfhe.encrypt_by_pk(m, &mut rng);
    let m_d = vfhe.decrypt(&c);
    let v_d = vfhe.decode(m_d);

    assert_eq!(v, v_d);

    let v1 = 1;
    let m1 = vfhe.encode(v1);
    let c1 = vfhe.encrypt_by_pk(m1, &mut rng);
    let c2 = c.clone().add_component_wise(&c1);
    let m_2 = vfhe.decrypt(&c2);
    let v_2 = vfhe.decode(m_2);
    assert_eq!(v_2, (v + v1) % 4);

    let ksk = vfhe.generate_key_switching_key(&rlwe_sk, &sk, rng);
    vfhe.set_ksk(ksk);

    let bks = vfhe.generate_bootstrapping_key();
    vfhe.set_bks(bks);
    let nand = vfhe.nand(c, &c1);
    let m_3 = vfhe.decrypt(&nand);
    let v_3 = vfhe.decode(m_3);
    assert_eq!(v_3, 1 - v * v1);
}

#[derive(Ring, Random)]
#[modulus = 512]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct FF(u32);
