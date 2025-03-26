use std::thread;

use algebra::Field;
use fhe_core::LweSecretKey;
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use thfhe::{distdec, Evaluator, Fp, KeyGen, DEFAULT_128_BITS_PARAMETERS};

// const LWE_MODULUS: u64 = 4096;
const RING_MODULUS: u64 = Fp::MODULUS_VALUE;

fn main() {
    const NUM_PARTIES: u32 = 3;
    const THRESHOLD: u32 = 1;
    const BASE_PORT: u32 = 30000;

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
        5600,
        participants,
        parameters.ring_dimension(),
        true,
    );

    let (sk, pk, evk) = KeyGen::generate_mpc_key_pair(&mut backend, **parameters, rng);
    println!(
        "Party {} has generated the secret key, public key, and evaluation key.",
        party_id
    );

    let lwe_sk: Vec<u64> = backend
        .reveal_slice_to_all(sk.input_lwe_secret_key.as_ref())
        .unwrap();

    let _lwe_sk = LweSecretKey::new(lwe_sk, fhe_core::LweSecretKeyType::Ternary);

    let evaluator = Evaluator::new(evk);

    let test_num = 16;
    let mut public_a: Vec<Vec<u64>> = Vec::with_capacity(test_num);
    let mut public_b: Vec<u64> = Vec::new();

    backend.init_z2k_triples_from_files();
    let a = 3;
    let b = 3;

    for _i in 0..test_num {
        let x = pk.encrypt(a, lwe_params, rng);
        let y = pk.encrypt(b, lwe_params, rng);

        //println!("Party {} is adding {} and {}", party_id, a, b);

        // let a_d: u64 = lwe_sk.decrypt(&x, lwe_params);
        // assert_eq!(a, a_d);

        // let b_d: u64 = lwe_sk.decrypt(&y, lwe_params);
        // assert_eq!(b, b_d);

        let res = evaluator.add(&x, &y);

        public_a.push(backend.sends_slice_to_all_parties(Some(res.a()), res.a().len(), 0));
        public_b.push(
            backend.sends_slice_to_all_parties(Some(&vec![res.b()]), vec![res.b()].len(), 0)[0],
        );
    }

    if party_id <= threshold {
        let my_sk = sk.input_lwe_secret_key.as_ref();

        let my_dd_res = distdec(&mut backend, rng, &public_a, &public_b, my_sk);

        if party_id == 0 {
            println!(
                "(a + b )%4= {}, my party id: {}, my dd result: {:?}",
                (a + b) % 4,
                backend.party_id(),
                my_dd_res.unwrap()
            );
        }
    }

    println!("Party {} took {:?} to finish.", party_id, start.elapsed());
    //println!("IO statistics: {:#?}", backend.netio.get_stats().unwrap());
}
