use fhe_cmp::{
    compare::{decrypt, encrypt, Compare},
    parameters::{DEFAULT_PARAMERTERS, DELTA, FF, HALF_DELTA},
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;
use std::{cmp::Ordering, time::Instant};
fn main() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let poly_length = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = Compare::new(&RLWEBlindRotationKey::generate(&sk));
    for i in 0..50 {
        let start = Instant::now();
        println!("{i}");
        let x = rng.gen_range(0..100000);
        let y = rng.gen_range(0..100000);
        let (value1, value2) = encrypt(
            x,
            y,
            sk.ntt_ring_secret_key(),
            basis,
            DELTA,
            sampler,
            &mut rng,
        );
        let (lt, eq, gt) = join_bit_opearions(&value1, &value2, &rotationkey, poly_length);
        let lt_value = decrypt(rlwe_sk, lt);
        let eq_value = decrypt(rlwe_sk, eq);
        let gt_value = decrypt(rlwe_sk, gt);

        match (x.cmp(&y), lt_value, eq_value, gt_value) {
            (Ordering::Less, lv, ev, gv)
                if lv != 1
                    || ev != param.lwe_plain_modulus() - 1
                    || gv != param.lwe_plain_modulus() - 1 =>
            {
                println!("          error1!:{lv}:{ev}:{gv}");
            }
            (Ordering::Equal, lv, ev, gv)
                if lv != param.lwe_plain_modulus() - 1
                    || ev != 1
                    || gv != param.lwe_plain_modulus() - 1 =>
            {
                println!("          error2!:{lv}:{ev}:{gv}");
            }
            (Ordering::Greater, lv, ev, gv)
                if lv != param.lwe_plain_modulus() - 1
                    || ev != param.lwe_plain_modulus() - 1
                    || gv != 1 =>
            {
                println!("          error3!:{lv}:{ev}:{gv}");
            }
            _ => {} // No error, do nothing
        }

        let time = start.elapsed();
        println!("Time: {}ms", time.as_millis());
    }
}

fn join_bit_opearions(
    value1: &[RLWE<FF>],
    value2: &[NTTRGSW<FF>],
    rotationkey: &Compare<FF>,
    ring_dimension: usize,
) -> (LWE<FF>, LWE<FF>, LWE<FF>) {
    let mut ct_lt: Option<LWE<FF>> = None;
    let mut ct_eq: Option<LWE<FF>> = None;
    let mut ct_gt: Option<LWE<FF>> = None;
    rayon::scope(|s| {
        s.spawn(|_| {
            ct_lt = Some(Compare::less_arbhcmp(
                rotationkey,
                value1,
                value2,
                DELTA,
                HALF_DELTA,
                ring_dimension,
            ))
        });
        s.spawn(|_| {
            ct_eq = Some(Compare::equality_arbhcmp(
                rotationkey,
                value1,
                value2,
                ring_dimension,
                DELTA,
            ))
        });
        s.spawn(|_| {
            ct_gt = Some(Compare::greater_arbhcmp(
                rotationkey,
                value1,
                value2,
                DELTA,
                HALF_DELTA,
                ring_dimension,
            ))
        });
    });
    (ct_lt.unwrap(), ct_eq.unwrap(), ct_gt.unwrap())
}
