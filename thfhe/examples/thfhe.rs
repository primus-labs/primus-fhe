use std::thread;

use algebra::Field;
use fhe_core::LweSecretKey;
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use thfhe::{distdec, Evaluator, Fp, KeyGen, DEFAULT_128_BITS_PARAMETERS};

// const LWE_MODULUS: u64 = 4096;
const RING_MODULUS: u64 = Fp::MODULUS_VALUE;
// type Msg = u64;

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

fn test_dd(party_id: u32, num_parties: u32, threshold: u32, base_port: u32) {
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
    );

    let sk: Vec<u64> = vec![1, 1, 1, 1, 1];
    let lwe_sk_shares = backend.input_slice(Some(&sk), 5, 0).unwrap();

    let lwe_sk: Vec<u64> = backend.reveal_slice_to_all(&lwe_sk_shares).unwrap();
    println!("LWE sk:{:?}", lwe_sk);
    if party_id <= threshold {
        //println!(" my sk length:{}, sk: {:?}",my_sk.len(), my_sk);
        println!("myid:{},LWE sk shares:{:?}", party_id, lwe_sk_shares);
        let my_dd_res = backend.shamir_secrets_to_additive_secrets(&lwe_sk_shares);
        let lwe_sk = backend.reveal_slice_z2k(&lwe_sk_shares, 0);
        println!("myid:{},LWE sk:{:?}", party_id, lwe_sk);
    }
    println!("RING_MODULUS-1={}", RING_MODULUS - 1125899906826240);
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
    );

    let (sk, pk, evk) = KeyGen::generate_mpc_key_pair(&mut backend, **parameters, rng);
    println!(
        "Party {} has generated the secret key, public key, and evaluation key.",
        party_id
    );

    let lwe_sk: Vec<u64> = backend
        .reveal_slice_to_all(sk.input_lwe_secret_key.as_ref())
        .unwrap();

    // let temp: Vec<i64> = lwe_sk
    // .iter()
    // .map(|x| {
    //     if *x == RING_MODULUS - 1 {
    //         -1
    //     } else {
    //         *x as i64
    //     }
    // })
    // .collect();

    // println!("LWE sk:{:?}",temp);

    let lwe_sk = LweSecretKey::new(lwe_sk, fhe_core::LweSecretKeyType::Ternary);

    let evaluator = Evaluator::new(evk);
    let a: u64 = 1;
    let b: u64 = 2;
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

            let public_a = backend.sends_slice_to_all_parties(Some(res.a()), res.a().len(), 0);
            let public_b =
                backend.sends_slice_to_all_parties(Some(&vec![res.b()]), vec![res.b()].len(), 0)[0];
            if party_id <= threshold {
                let my_sk = sk.input_lwe_secret_key.as_ref();
                //println!(" my sk length:{}, sk: {:?}",my_sk.len(), my_sk);

                let my_dd_res = distdec(&mut backend, rng, &public_a, public_b, my_sk);

                //let plain: u64 = lwe_sk.decrypt(&res, lwe_params);

                // assert_eq!((a + b) % 4, plain);
                if party_id == 0 {
                    println!(
                        "(a + b )%4= {}, my party id: {}, my dd result: {}",
                        (a + b) % 4,
                        backend.party_id(),
                        my_dd_res.unwrap()
                    );
                }
            }
        }
    }
    println!("Party {} took {:?} to finish.", party_id, start.elapsed());
    println!("IO statistics: {:#?}", backend.netio.get_stats().unwrap());
}
