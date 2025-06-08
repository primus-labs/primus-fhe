use algebra::{
    modulus::{BarrettModulus, PowOf2Modulus},
    reduce::ModulusValue,
};
use fhe_core::{
    lwe_modulus_switch, KeySwitchingParameters, LweParameters, LwePublicKey, LwePublicKeyRlweMode,
    LweSecretKey, LweSecretKeyType, NonPowOf2LweKeySwitchingKey,
};
use lattice::Lwe;
use rand::{distributions::Uniform, thread_rng, Rng};

#[test]
fn test_lwe_pk() {
    type MsgT = u8;
    type CipherT = u16;
    type Modulus = PowOf2Modulus<CipherT>;

    let mut rng = thread_rng();

    let plian_modulus = 4;
    let cipher_modulus = 1 << 14;

    let distr = Uniform::new(0, plian_modulus);

    let modulus = Modulus::new(cipher_modulus);

    let params = LweParameters {
        dimension: 512,
        plain_modulus_value: plian_modulus as CipherT,
        cipher_modulus_value: ModulusValue::PowerOf2(cipher_modulus),
        cipher_modulus_minus_one: cipher_modulus - 1,
        cipher_modulus: modulus,
        secret_key_type: LweSecretKeyType::Binary,
        noise_standard_deviation: 3.20,
    };

    // generate secret key
    let sk = LweSecretKey::generate(&params, &mut rng);

    // encrypt message with secret key
    let message: MsgT = rng.sample(distr);
    let c: Lwe<u16> = sk.encrypt(message, &params, &mut rng);
    let m: MsgT = sk.decrypt(&c, &params);
    assert_eq!(m, message);

    // encrypt multi messages with secret key
    let messages: Vec<MsgT> = (&mut rng).sample_iter(distr).take(256).collect();
    let c = sk.encrypt_multi_messages(&messages, &params, &mut rng);
    let index = rng.gen_range(0..256);
    let c1 = c.extract_rlwe_mode(index, modulus);
    let m: MsgT = sk.decrypt(&c1, &params);
    assert_eq!(m, messages[index]);
    let msgs = sk.decrypt_multi_messages::<MsgT, Modulus>(&c, &params);
    assert_eq!(msgs, messages);

    // generate public key
    let pk = LwePublicKey::new(&sk, &params, &mut rng);

    // encrypt message with public key
    let message: MsgT = rng.sample(distr);
    let c = pk.encrypt(message, &params, &mut rng);
    let m: MsgT = sk.decrypt(&c, &params);
    assert_eq!(m, message);

    // generate public key
    let pk2 = LwePublicKeyRlweMode::new(&sk, &params, &mut rng);

    // encrypt message with public key
    let message: MsgT = rng.sample(distr);
    let c: Lwe<u16> = pk2.encrypt(message, &params, &mut rng);
    let m: MsgT = sk.decrypt(&c, &params);
    assert_eq!(m, message);

    // encrypt multi messages with public key
    let c = pk2.encrypt_multi_messages(&messages, &params, &mut rng);
    let index = rng.gen_range(0..256);
    let c1 = c.extract_rlwe_mode(index, modulus);
    let m: MsgT = sk.decrypt(&c1, &params);
    assert_eq!(m, messages[index]);
    let msgs = sk.decrypt_multi_messages::<MsgT, Modulus>(&c, &params);
    assert_eq!(msgs, messages);
}

#[test]
fn test_key_switch() {
    type MsgT = u8;
    type CipherT = u32;
    type ModulusIn = BarrettModulus<CipherT>;
    type ModulusOut = PowOf2Modulus<CipherT>;

    let mut rng = thread_rng();

    let plain_modulus_value = 32;
    let cipher_modulus_value_in = 134215681;
    let cipher_modulus_value_out = 4096;
    let modulus_in = ModulusIn::new(cipher_modulus_value_in);
    let modulus_out = ModulusOut::new(cipher_modulus_value_out);

    let msg_distr = Uniform::new(0, plain_modulus_value);

    let params_in = LweParameters {
        dimension: 1024,
        plain_modulus_value: plain_modulus_value as CipherT,
        cipher_modulus_value: ModulusValue::Prime(cipher_modulus_value_in),
        cipher_modulus_minus_one: cipher_modulus_value_in - 1,
        cipher_modulus: modulus_in,
        secret_key_type: LweSecretKeyType::Ternary,
        noise_standard_deviation: 3.20,
    };

    let params_out = LweParameters {
        dimension: 127,
        plain_modulus_value: plain_modulus_value as CipherT,
        cipher_modulus_value: ModulusValue::PowerOf2(cipher_modulus_value_out),
        cipher_modulus_minus_one: cipher_modulus_value_out - 1,
        cipher_modulus: modulus_out,
        secret_key_type: LweSecretKeyType::Binary,
        noise_standard_deviation: 3.20,
    };

    let key_switching_key_params = KeySwitchingParameters {
        input_cipher_dimension: params_in.dimension,
        output_cipher_dimension: params_out.dimension,
        log_modulus: params_in.cipher_modulus_value.log_modulus(),
        log_basis: 1,
        reverse_length: None,
        noise_standard_deviation: 3.2,
    };

    // generate secret key
    let sk_in = LweSecretKey::generate(&params_in, &mut rng);
    let sk_out = LweSecretKey::generate(&params_out, &mut rng);

    // generate key switching key
    let key_switch_key = NonPowOf2LweKeySwitchingKey::generate(
        &sk_in,
        &sk_out,
        key_switching_key_params,
        modulus_in,
        &mut rng,
    );

    for i in 0..20 {
        // encrypt message with secret key
        let message: MsgT = rng.sample(msg_distr);
        let c: Lwe<u32> = sk_in.encrypt(message, &params_in, &mut rng);
        let m: MsgT = sk_in.decrypt(&c, &params_in);
        assert_eq!(m, message);
        println!("encrypt and decrypt done");

        // key switch
        let c2 = key_switch_key.key_switch(&c, modulus_in);
        println!("key switch done");

        // modulus switch
        let c3 = lwe_modulus_switch(
            &c2,
            cipher_modulus_value_in,
            params_out.cipher_modulus_value,
        );
        println!("modulus switch done");

        // decrypt
        let m: MsgT = sk_out.decrypt(&c3, &params_out);
        assert_eq!(m, message);
        println!("round {} done", i);
    }
}
