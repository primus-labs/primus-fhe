use algebra::modulus::PowOf2Modulus;
use fhe_core::{
    LweParameters, LwePublicKey, LwePublicKeyRlweMode, LweSecretKey, LweSecretKeyType, ModulusValue,
};
use rand::{distributions::Uniform, thread_rng, Rng};

#[test]
fn test_lwe_pk() {
    type MsgT = u8;
    type CipherT = u16;

    let mut rng = thread_rng();

    let plian_modulus = 4;
    let cipher_modulus = 2048;

    let distr = Uniform::new(0, plian_modulus);

    let modulus = <PowOf2Modulus<CipherT>>::new(cipher_modulus);

    let params = LweParameters::<CipherT> {
        dimension: 512,
        plain_modulus_value: plian_modulus as CipherT,
        cipher_modulus_value: ModulusValue::PowerOf2(cipher_modulus),
        cipher_modulus_minus_one: cipher_modulus - 1,
        secret_key_type: LweSecretKeyType::Binary,
        noise_standard_deviation: 3.20,
    };

    let gaussian = params.noise_distribution();

    // generate secret key
    let sk = LweSecretKey::generate(&params, &mut rng);

    // encrypt message with secret key
    let message: MsgT = rng.sample(distr);
    let c = sk.encrypt::<MsgT, _>(message, &params, modulus, &mut rng);
    let m = sk.decrypt::<MsgT>(&c, &params, modulus);
    assert_eq!(m, message);

    // generate public key
    let pk = LwePublicKey::new(&sk, &params, modulus, gaussian, &mut rng);

    // encrypt message with public key
    let message: MsgT = rng.sample(distr);
    let c = pk.encrypt(message, &params, modulus, &mut rng);
    let m = sk.decrypt::<MsgT>(&c, &params, modulus);
    assert_eq!(m, message);

    // generate public key
    let pk2 = LwePublicKeyRlweMode::new(&sk, &params, modulus, &mut rng);

    // encrypt message with public key
    let message: MsgT = rng.sample(distr);
    let c = pk2.encrypt(message, &params, modulus, &mut rng);
    let m = sk.decrypt::<MsgT>(&c, &params, modulus);
    assert_eq!(m, message);

    // encrypt multi messages with public key
    let messages: Vec<MsgT> = (&mut rng).sample_iter(distr).take(256).collect();
    let c = pk2.encrypt_multi_messages(&messages, &params, modulus, &mut rng);
    let index = rng.gen_range(0..256);
    let c1 = c.extract_rlwe_mode(index, modulus);
    let m = sk.decrypt::<MsgT>(&c1, &params, modulus);
    assert_eq!(m, messages[index]);
}
