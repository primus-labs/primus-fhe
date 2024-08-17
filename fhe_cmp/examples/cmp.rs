use fhe_cmp::comparison::{self, decrypt, initial, DEELTA, HALF_DEELTA};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use rand::prelude::*;

fn main() {
    let mut rng = thread_rng();

    let param = *comparison::DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);

    let basis = param.blind_rotation_basis();
    let ring_dimension = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
    let rotationkey = RLWEBlindRotationKey::generate(&sk, sampler, &mut rng);

    for i in 0..50 {
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

        let lt = comparison::less_arbhcmp(
            &value1,
            &value2,
            &rotationkey,
            DEELTA,
            HALF_DEELTA,
            ring_dimension,
        );
        let eq = comparison::equality_arbhcmp(&value1, &value2, &rotationkey, ring_dimension);
        let gt = comparison::greater_arbhcmp(
            &value1,
            &value2,
            &rotationkey,
            DEELTA,
            HALF_DEELTA,
            ring_dimension,
        );

        let lt_value = decrypt(rlwe_sk, lt);
        let eq_value = decrypt(rlwe_sk, eq);
        let gt_value = decrypt(rlwe_sk, gt);
        //println!("less:{}",decoded_value1);
        //println!("equal:{}",decoded_value2);
        //println!("greater:{}",decoded_value3);
        if x < y {
            if lt_value != 1 || eq_value != 0 || gt_value != 0 {
                println!("error1!:{lt_value}:{eq_value}:{gt_value}");
            }
        } else if x == y {
            if lt_value != 0 || eq_value != 1 || gt_value != 0 {
                println!("error2!:{lt_value}:{eq_value}:{gt_value}");
            }
        } else {
            if lt_value != 0 || eq_value != 0 || gt_value != 1 {
                println!("error3!:{lt_value}:{eq_value}:{gt_value}");
            }
        }
    }
}
