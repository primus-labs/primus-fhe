use fhe_cmp::{
    compare::{decrypt, Encryptor, HomomorphicCmpScheme},
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

    let neg_one = param.lwe_plain_modulus() - 1;

    let skp = SecretKeyPack::new(param);
    let rlwe_sk = skp.ring_secret_key().as_slice();
    let rotationkey = HomomorphicCmpScheme::new(&skp);
    let encryptor = Encryptor::new(&skp);

    let time = start.elapsed();
    println!("Start Time: {}ms", time.as_millis());

    for i in 0..10 {
        println!("{i}");
        let x = rng.gen_range(0..(1 << 30));
        let y = rng.gen_range(0..(1 << 30));

        let mut value1 = encryptor.rlwe_encrypt(x, &mut rng);
        let mut value2 = encryptor.rgsw_encrypt(y, &mut rng);
        encryptor.align(&mut value1, &mut value2, &mut rng);

        let start = Instant::now();
        let (lt, eq, gt) = join_bit_operations(&value1, &value2, &rotationkey);
        println!("Time: {}ms", start.elapsed().as_millis());

        let lt_value = decrypt(rlwe_sk, lt);
        let eq_value = decrypt(rlwe_sk, eq);
        let gt_value = decrypt(rlwe_sk, gt);

        match (x.cmp(&y), lt_value, eq_value, gt_value) {
            (Ordering::Less, lv, ev, gv) if lv != 1 || ev != neg_one || gv != neg_one => {
                println!("          error1!:{lv}:{ev}:{gv}");
            }
            (Ordering::Equal, lv, ev, gv) if lv != neg_one || ev != 1 || gv != neg_one => {
                println!("          error2!:{lv}:{ev}:{gv}");
            }
            (Ordering::Greater, lv, ev, gv) if lv != neg_one || ev != neg_one || gv != 1 => {
                println!("          error3!:{lv}:{ev}:{gv}");
            }
            _ => {} // No error, do nothing
        }
    }
}

fn join_bit_operations(
    value1: &[RLWE<FF>],
    value2: &[NTTRGSW<FF>],
    rotationkey: &HomomorphicCmpScheme<u32, FF>,
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
