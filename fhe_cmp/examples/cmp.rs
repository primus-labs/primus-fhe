use fhe_cmp::comparison::{self, decrypt, initial, DEELTA, HALF_DEELTA};
use fhe_core::{RLWEBlindRotationKey, SecretKeyPack};
use rand::prelude::*;

fn main() {
    let mut rng = thread_rng();
    let param = *comparison::DEFAULT_PARAMERTERS;
    let sk = SecretKeyPack::new(param);
    let basis = param.blind_rotation_basis();
    let poly_length = param.ring_dimension();
    let sampler = param.ring_noise_distribution();
    let rlwe_sk = sk.ring_secret_key().as_slice();
for _ in 0..50{
    let rotationkey = RLWEBlindRotationKey::generate(&sk, sampler, &mut rng);
    let x = rng.gen_range(0..100000000);
    let y = rng.gen_range(0..100000000);
    //println!("{},{}",x,y);
    let (value1,value2) = initial(
        x, 
        y, 
        param.ring_dimension(),
        sk.ntt_ring_secret_key(),
        sampler,
        &mut rng,
        basis,
        HALF_DEELTA,
    );
    let out1 = comparison::less_arbhcmp(&value1, &value2, &rotationkey, DEELTA, HALF_DEELTA, poly_length);
    let out2 = comparison::equality_arbhcmp(&value1,&value2, &rotationkey,poly_length);
    let out3 = comparison::greater_arbhcmp(&value1, &value2, &rotationkey, DEELTA, HALF_DEELTA, poly_length);
    let decoded_value1 = decrypt(rlwe_sk, out1);
    let decoded_value2 = decrypt(rlwe_sk, out2);
    let decoded_value3 = decrypt(rlwe_sk, out3);
    //println!("less:{}",decoded_value1);
    //println!("equal:{}",decoded_value2);
    //println!("greater:{}",decoded_value3);
    if x < y {
        if decoded_value1 != 1 || decoded_value2 != 0 || decoded_value3 != 0{
            println!("error1!");
        }
    }else if x == y {
        if decoded_value1 != 0 || decoded_value2 != 1 || decoded_value3 != 0{
            println!("error2!");
        }
    }else{
        if decoded_value1 != 0 || decoded_value2 != 0 || decoded_value3 != 1{
            println!("error3!");
        }
    }
}
}

