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
    const BASE_PORT: u32 = 50000;

    let threads = (0..NUM_PARTIES)
        .map(|party_id| thread::spawn(move || thfhe(party_id, NUM_PARTIES, THRESHOLD, BASE_PORT)))
        .collect::<Vec<_>>();

    for handle in threads {
        handle.join().unwrap();
    }
}

fn thfhe(party_id: u32, num_parties: u32, threshold: u32, base_port: u32) {
    let start = std::time::Instant::now();

    let rng = &mut rand::thread_rng();

    let parameters = &DEFAULT_128_BITS_PARAMETERS;
    let lwe_params = parameters.input_lwe_params();

    // Setup the DN backend.
    let participants = Participant::from_default(num_parties, base_port);
    let mut backend = DNBackend::<RING_MODULUS>::new(
        party_id,
        num_parties,
        threshold,
        20000,
        participants,
        parameters.ring_dimension(),
    );

    let (sk, pk, evk) = KeyGen::generate_mpc_key_pair(&mut backend, **parameters, rng);
    println!(
        "Party {} has generated the secret key, public key, and evaluation key.",
        party_id
    );

    let lwe_sk: Vec<u64> = sk
        .input_lwe_secret_key
        .as_ref()
        .iter()
        .map(|s| backend.reveal_to_all(*s).unwrap())
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

    println!("Party {} took {:?} to finish.", party_id, start.elapsed());
}
