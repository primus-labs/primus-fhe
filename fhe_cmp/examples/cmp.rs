use std::time::Instant;

use fhe_cmp::comparison::{
    decrypt, equality_arbhcmp, greater_arbhcmp, initial, less_arbhcmp, DefaultField, DEELTA,
    DEFAULT_PARAMERTERS, HALF_DEELTA,
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;

fn main() {
    let mut rng = thread_rng();

    let param = *DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);

    let basis = param.blind_rotation_basis();
    let ring_dimension = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = RLWEBlindRotationKey::generate(&sk, sampler, &mut rng);

    for i in 0..50 {
        let start = Instant::now();
        println!("{i}");
        let x = rng.gen_range(0..100000000);
        let y = rng.gen_range(0..100000000);
        //println!("{},{}",x,y);

        let (value1, value2) = initial(
            x,
            y,
            sk.ntt_ring_secret_key(),
            basis,
            HALF_DEELTA,
            sampler,
            &mut rng,
        );

        println!("length:{}", value1.len());

        let (lt, eq, gt) = join_bit_opearions(&value1, &value2, &rotationkey, ring_dimension);

        let lt_value = decrypt(rlwe_sk, lt);
        let eq_value = decrypt(rlwe_sk, eq);
        let gt_value = decrypt(rlwe_sk, gt);
        //println!("less:{}",decoded_value1);
        //println!("equal:{}",decoded_value2);
        //println!("greater:{}",decoded_value3);
        if x < y {
            if lt_value != 1 || eq_value != 0 || gt_value != 0 {
                println!("          error1!:{lt_value}:{eq_value}:{gt_value}");
            }
        } else if x == y {
            if lt_value != 0 || eq_value != 1 || gt_value != 0 {
                println!("          error2!:{lt_value}:{eq_value}:{gt_value}");
            }
        } else {
            if lt_value != 0 || eq_value != 0 || gt_value != 1 {
                println!("          error3!:{lt_value}:{eq_value}:{gt_value}");
            }
        }

        let time = start.elapsed();
        println!("Time: {}ms", time.as_millis());
    }
}

fn join_bit_opearions(
    value1: &[RLWE<DefaultField>],
    value2: &[NTTRGSW<DefaultField>],
    rotationkey: &RLWEBlindRotationKey<DefaultField>,
    ring_dimension: usize,
) -> (LWE<DefaultField>, LWE<DefaultField>, LWE<DefaultField>) {
    let mut ct_lt: Option<LWE<DefaultField>> = None;
    let mut ct_eq: Option<LWE<DefaultField>> = None;
    let mut ct_gt: Option<LWE<DefaultField>> = None;

    rayon::scope(|s| {
        s.spawn(|_| {
            ct_lt = Some(less_arbhcmp(
                &value1,
                &value2,
                &rotationkey,
                DEELTA,
                HALF_DEELTA,
                ring_dimension,
            ))
        });
        s.spawn(|_| {
            ct_eq = Some(equality_arbhcmp(
                &value1,
                &value2,
                &rotationkey,
                ring_dimension,
            ))
        });
        s.spawn(|_| {
            ct_gt = Some(greater_arbhcmp(
                &value1,
                &value2,
                &rotationkey,
                DEELTA,
                HALF_DEELTA,
                ring_dimension,
            ))
        });
    });
    (ct_lt.unwrap(), ct_eq.unwrap(), ct_gt.unwrap())
}
