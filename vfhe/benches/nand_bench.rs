use criterion::{criterion_group, criterion_main, Criterion};

use algebra::derive::{Field, Prime, Random, Ring, NTT};
use vfhe::{LWEParam, LWESecretKeyDistribution, RingParam, Vfhe};

#[derive(Ring, Random)]
#[modulus = 1024]
pub struct RR(u32);

#[derive(Ring, Field, Random, Prime, NTT)]
#[modulus = 1073692673]
pub struct FF(u32);

pub fn criterion_benchmark(c: &mut Criterion) {
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
    let rlwe_sk = vfhe.rlwe().generate_sk(&mut rng);
    let rlwe_sk_ntt = rlwe_sk.clone().to_ntt_polynomial();
    let rlwe_pk = vfhe.rlwe().generate_pk(&rlwe_sk_ntt, &mut rng);
    let ksk = vfhe.generate_key_switching_key(&rlwe_sk, &sk, &mut rng);
    let bks = vfhe.generate_bootstrapping_key(&sk, &rlwe_sk_ntt, &mut rng);

    vfhe.set_secret_key(Some(sk));
    vfhe.set_public_key(pk);
    vfhe.rlwe_mut().set_secret_key(Some((rlwe_sk, rlwe_sk_ntt)));
    vfhe.rlwe_mut().set_public_key(rlwe_pk);
    vfhe.set_key_switching_key(ksk);
    vfhe.set_bootstrapping_key(bks);

    let v0 = if rand::random() { 1 } else { 0 };
    let m0 = vfhe.encode(v0);
    let c0 = vfhe.encrypt_by_pk(m0, &mut rng);

    let v1 = if rand::random() { 1 } else { 0 };
    let m1 = vfhe.encode(v1);
    let c1 = vfhe.encrypt_by_pk(m1, &mut rng);

    c.bench_function("nand", |b| {
        b.iter(|| {
            let nand = vfhe.nand(c0.clone(), &c1);
            let _nand_floor: lattice::LWE<RR> = nand.modulus_switch_floor(vfhe.ql(), vfhe.qr());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
