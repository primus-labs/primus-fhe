use fhe_cmp::{
    compare::{decrypt, Encryptor, HomeCmpScheme},
    parameters::{DEFAULT_PARAMETERS, FF},
};
use fhe_core::SecretKeyPack;
use lattice::{LWE, NTTRGSW, RLWE};
use rand::prelude::*;
use std::{cmp::Ordering, time::Instant};
fn main() {
    let start = Instant::now();
    let mut rng = thread_rng();
    let param = *DEFAULT_PARAMETERS;
    let sk = SecretKeyPack::new(param);
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = HomeCmpScheme::new(&sk);
    let enc_elements = Encryptor::new(&sk);
    let time = start.elapsed();
    println!("Start Time: {}ms", time.as_millis());
    for i in 0..10 {
        println!("{i}");
        let x = rng.gen_range(0..1000000);
        let y = rng.gen_range(0..1000000);
        let value1 = enc_elements.rlwe_encrypt(x, &mut rng);
        let value2 = enc_elements.rgsw_encrypt(y, &mut rng);
        let (value1, value2) = enc_elements.align(value1, value2, &mut rng);
        let (lt, eq, gt) = join_bit_operations(&value1, &value2, &rotationkey);
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

fn join_bit_operations(
    value1: &[RLWE<FF>],
    value2: &[NTTRGSW<FF>],
    rotationkey: &HomeCmpScheme<u64, FF>,
) -> (LWE<FF>, LWE<FF>, LWE<FF>) {
    let mut ct_lt: Option<LWE<FF>> = None;
    let mut ct_eq: Option<LWE<FF>> = None;
    let mut ct_gt: Option<LWE<FF>> = None;
    rayon::scope(|s| {
        s.spawn(|_| ct_lt = Some(rotationkey.lt_arbhcmp(value1, value2)));
        s.spawn(|_| ct_eq = Some(rotationkey.eq_arbhcmp(value1, value2)));
        s.spawn(|_| ct_gt = Some(rotationkey.gt_arbhcmp(value1, value2)));
    });
    (ct_lt.unwrap(), ct_eq.unwrap(), ct_gt.unwrap())
}
