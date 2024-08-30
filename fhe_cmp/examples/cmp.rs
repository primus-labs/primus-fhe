use fhe_cmp::{
    compare::{decrypt, encrypt, HomCmpScheme},
    parameters::{DEFAULT_PARAMERTERS, DELTA, FF, HALF_DELTA},
};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;
use std::time::Instant;
fn main() {
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let poly_length = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomCmpScheme::new(RLWEBlindRotationKey::generate(&sk), param);
    for i in 0..20 {
        let start = Instant::now();
        println!("{i}");
        let x = rng.gen_range(0..1000000000);
        let y = rng.gen_range(0..1000000000);
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
        /*println!("
        x:{},
        y:{},
        less:{}
        equal:{}
        greater:{}",x,y,lt_value,eq_value,gt_value);*/
        if x < y {
            if lt_value != 1
                || eq_value != param.lwe_plain_modulus() - 1
                || gt_value != param.lwe_plain_modulus() - 1
            {
                println!("          error1!:{lt_value}:{eq_value}:{gt_value}");
            }
        } else if x == y {
            if lt_value != param.lwe_plain_modulus() - 1
                || eq_value != 1
                || gt_value != param.lwe_plain_modulus() - 1
            {
                println!("          error2!:{lt_value}:{eq_value}:{gt_value}");
            }
        } else {
            if lt_value != param.lwe_plain_modulus() - 1
                || eq_value != param.lwe_plain_modulus() - 1
                || gt_value != 1
            {
                println!("          error3!:{lt_value}:{eq_value}:{gt_value}");
            }
        }
        let time = start.elapsed();
        println!("Time: {}ms", time.as_millis());
    }
}

fn join_bit_opearions(
    value1: &[RLWE<FF>],
    value2: &[NTTRGSW<FF>],
    rotationkey: &HomCmpScheme<u64, FF>,
    ring_dimension: usize,
) -> (LWE<FF>, LWE<FF>, LWE<FF>) {
    let mut ct_lt: Option<LWE<FF>> = None;
    let mut ct_eq: Option<LWE<FF>> = None;
    let mut ct_gt: Option<LWE<FF>> = None;
    rayon::scope(|s| {
        s.spawn(|_| {
            ct_lt = Some(HomCmpScheme::less_arbhcmp(
                &rotationkey,
                &value1,
                &value2,
                DELTA,
                HALF_DELTA,
                ring_dimension,
            ))
        });
        s.spawn(|_| {
            ct_eq = Some(HomCmpScheme::equality_arbhcmp(
                &rotationkey,
                &value1,
                &value2,
                ring_dimension,
                DELTA,
            ))
        });
        s.spawn(|_| {
            ct_gt = Some(HomCmpScheme::greater_arbhcmp(
                &rotationkey,
                &value1,
                &value2,
                DELTA,
                HALF_DELTA,
                ring_dimension,
            ))
        });
    });
    (ct_lt.unwrap(), ct_eq.unwrap(), ct_gt.unwrap())
}
