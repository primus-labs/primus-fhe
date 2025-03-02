use std::thread;

use algebra::Field;
use fhe_core::LweSecretKey;
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use thfhe::{Evaluator, Fp, KeyGen, DEFAULT_128_BITS_PARAMETERS};

// const LWE_MODULUS: u64 = 4096;
const RING_MODULUS: u64 = Fp::MODULUS_VALUE;

// type Msg = u64;

fn main() {
    const NUM_PARTIES: u32 = 3;
    const THRESHOLD: u32 = 1;
    const BASE_PORT1: u32 = 50000;
    const BASE_PORT2: u32 = 60000;

    let threads = (0..NUM_PARTIES)
        .map(|party_id| {
            thread::spawn(move || thfhe(party_id, NUM_PARTIES, THRESHOLD, BASE_PORT1, BASE_PORT2))
        })
        .collect::<Vec<_>>();

    for handle in threads {
        handle.join().unwrap();
    }
}

fn thfhe(party_id: u32, num_parties: u32, threshold: u32, base_port1: u32, base_port2: u32) {
    let rng = &mut rand::thread_rng();

    // Setup the DN backend.
    let participants_q = Participant::from_default(num_parties, base_port1);
    let participants_big_q = Participant::from_default(num_parties, base_port2);
    let mut dn_q =
        DNBackend::<RING_MODULUS>::new(party_id, num_parties, threshold, 2000, participants_q);
    let mut dn_big_q =
        DNBackend::<RING_MODULUS>::new(party_id, num_parties, threshold, 2000, participants_big_q);
    // let mut dn_q = DummyBackend::<LWE_MODULUS> {};
    // let mut dn_big_q = DummyBackend::<RING_MODULUS> {};

    let parameters = &DEFAULT_128_BITS_PARAMETERS;

    let lwe_params = parameters.input_lwe_params();

    let (sk, pk, evk) = KeyGen::generate_mpc_key_pair(&mut dn_q, &mut dn_big_q, **parameters, rng);

    println!(
        "Party {} is generating the secret key, public key and evaluate key",
        party_id
    );

    let lwe_sk: Vec<u64> = sk
        .input_lwe_secret_key
        .as_ref()
        .iter()
        .map(|s| dn_big_q.reveal_to_all(*s).unwrap())
        .collect();

    let lwe_sk = LweSecretKey::new(lwe_sk, fhe_core::LweSecretKeyType::Ternary);

    let evaluator = Evaluator::new(evk);

    for a in 0..4 {
        for b in 0..4 {
            let x = pk.encrypt(a, lwe_params, rng);
            let y = pk.encrypt(b, lwe_params, rng);

            println!("Party {} is adding {} and {}", party_id, a, b);

            let a_d: u64 = lwe_sk.decrypt(&x, lwe_params);
            assert_eq!(a, a_d);

            let b_d: u64 = lwe_sk.decrypt(&y, lwe_params);
            assert_eq!(b, b_d);

            let res = evaluator.add(&x, &y);

            let plain: u64 = lwe_sk.decrypt(&res, lwe_params);

            // assert_eq!((a + b) % 4, plain);
            if (a + b) % 4 != plain {
                println!("Party {} got {}! Error!", party_id, plain);
            } else {
                println!("Party {} got {}!", party_id, plain);
            }
        }
    }
}
