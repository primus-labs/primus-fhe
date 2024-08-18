use fhe_cmp::comparison::{self, decrypt, initial, DELTA, HALF_DELTA};
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
    let x = rng.gen_range(0..100000);
    let y = rng.gen_range(0..100000);
    let (value1,value2) = initial(
        x, 
        y, 
        param.ring_dimension(),
        sk.ntt_ring_secret_key(),
        sampler,
        &mut rng,
        basis,
        DELTA,
    );
    let out1 = comparison::greater_arbhcmp(&value1, &value2, &rotationkey, DELTA, HALF_DELTA, poly_length);
    let out2 = comparison::less_arbhcmp(&value1, &value2, &rotationkey, DELTA, HALF_DELTA, poly_length);
    let out3 = comparison::equality_arbhcmp(&value1, &value2, &rotationkey, poly_length, DELTA);
    let decoded_value1 = decrypt(rlwe_sk, out1);
    let decoded_value2 = decrypt(rlwe_sk, out2);
    let decoded_value3 = decrypt(rlwe_sk, out3);
    if x > y {
        if decoded_value1 != 1 || decoded_value2 != 15 || decoded_value3 != 15{
            println!("error1");
        }
    }else if x < y {
        if decoded_value1 != 15 || decoded_value2 != 1 || decoded_value3 != 15{
            println!("error2");
        }
    }else{
        if decoded_value1 != 15 || decoded_value2 != 15 || decoded_value3 != 1{
            println!("error3");
        }
    }
}


}

