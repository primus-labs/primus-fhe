use algebra::derive::*;
use vfhe::{LweParam, Vfhe};

fn main() {
    let mut rng = rand::thread_rng();

    let lwe_param = <LweParam<RR>>::new(1024, 4, 512, 3.20);
    let mut vfhe: Vfhe<RR, FF> = Vfhe::new(lwe_param);

    let sk = vfhe.generate_ternary_sk(&mut rng);
    let pk = vfhe.generate_pk(&sk, &mut rng);
    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);

    let v = 0;
    let m = vfhe.encode(v);
    let c = vfhe.encrypt(m, &mut rng);
    let m_d = vfhe.decrypt(&c);
    let v_d = vfhe.decode(m_d);

    assert_eq!(v, v_d);

    let v1 = 1;
    let m1 = vfhe.encode(v1);
    let c1 = vfhe.encrypt(m1, &mut rng);
    let c2 = c.no_boot_add(&c1);
    let m_2 = vfhe.decrypt(&c2);
    let v_2 = vfhe.decode(m_2);
    assert_eq!(v_2, (v + v1) % 4);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Random)]
#[modulus = 512]
pub struct RR(u32);

#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Ring, Field, Random, Prime, NTT,
)]
#[modulus = 132120577]
pub struct FF(u32);
