use algebra::derive::*;
use vfhe::{LWEParam, RLWEParam, Vfhe};

fn main() {
    let mut rng = rand::thread_rng();

    let lwe_param = <LWEParam<RR>>::new(512, 4, 512, 3.20);
    let rlwe_param = <RLWEParam<FF>>::new(1024, 132120577, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe_param, rlwe_param, 2);

    let sk = vfhe.generate_ternary_lwe_sk(&mut rng);
    let pk = vfhe.generate_lwe_pk(&sk, &mut rng);
    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);

    let rlwe_sk = vfhe.rlwe_param().generate_sk(&mut rng);
    let rlwe_pk = vfhe.rlwe_param().generate_pk(&rlwe_sk, &mut rng);
    vfhe.rlwe_param_mut().set_secret_key(Some(rlwe_sk));
    vfhe.rlwe_param_mut().set_public_key(rlwe_pk);

    let v = 0;
    let m = vfhe.encode(v);
    let c = vfhe.encrypt_by_pk(m, &mut rng);
    let m_d = vfhe.decrypt(&c);
    let v_d = vfhe.decode(m_d);

    assert_eq!(v, v_d);

    let v1 = 1;
    let m1 = vfhe.encode(v1);
    let c1 = vfhe.encrypt_by_pk(m1, &mut rng);
    let c2 = c.no_boot_add(&c1);
    let m_2 = vfhe.decrypt(&c2);
    let v_2 = vfhe.decode(m_2);
    assert_eq!(v_2, (v + v1) % 4);
}

#[derive(Ring, Random)]
#[modulus = 512]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 132120577]
pub struct FF(u32);
