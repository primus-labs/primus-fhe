use fhe_cmp::{
    compare::{decrypt, Encryptor, HomomorphicCmpScheme},
    parameters::DEFAULT_PARAMETERS,
};
use fhe_core::SecretKeyPack;
use rand::prelude::*;
use std::cmp::Ordering;

fn main() {
    let mut rng = thread_rng();

    let param = *DEFAULT_PARAMETERS;

    let neg_one = param.lwe_plain_modulus() - 1;

    let skp = SecretKeyPack::new(param);
    let rlwe_sk = skp.ring_secret_key().as_slice();
    let rotationkey = HomomorphicCmpScheme::new(&skp);
    let encryptor = Encryptor::new(&skp);

    for i in 0..100 {
        println!("{i}");
        let x = rng.gen_range(0..(1 << 30));
        let y = rng.gen_range(0..(1 << 30));

        let mut value1 = encryptor.rlwe_encrypt(x, &mut rng);
        let mut value2 = encryptor.rgsw_encrypt(y, &mut rng);
        encryptor.align(&mut value1, &mut value2, &mut rng);

        let gt = rotationkey.gt_arbhcmp(&value1, &value2);

        let gt_value = decrypt(rlwe_sk, gt);

        match (x.cmp(&y), gt_value) {
            (Ordering::Less, gv) if gv != neg_one => {
                println!("          error1!:{gv}");
            }
            (Ordering::Equal, gv) if gv != neg_one => {
                println!("          error2!:{gv}");
            }
            (Ordering::Greater, gv) if gv != 1 => {
                println!("          error3!:{gv}");
            }
            _ => {} // No error, do nothing
        }
    }
}
