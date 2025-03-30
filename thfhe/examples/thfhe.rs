use std::thread;

use algebra::Field;
use clap::Parser;
use mpc::{DNBackend, MPCBackend};
use network::netio::Participant;
use thfhe::{distdec, Evaluator, Fp, KeyGen, DEFAULT_128_BITS_PARAMETERS};
// const LWE_MODULUS: u64 = 4096;
const RING_MODULUS: u64 = Fp::MODULUS_VALUE;
#[derive(Parser)]
struct Args {
    /// 参数 n
    #[arg(short = 'n')]
    n: u32,

    /// 参数 t
    #[arg(short = 't')]
    t: u32,
}

fn main() {
    let args = Args::parse();
    //const NUM_PARTIES: u32 =args.n;
    let number_parties = args.n;
    let number_threshold = args.t;
    //const THRESHOLD: u32 = args.t;
    const BASE_PORT: u32 = 20500;

    let threads = (0..number_parties)
        .map(|party_id| {
            thread::spawn(move || thfhe(party_id, number_parties, number_threshold, BASE_PORT))
        })
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
        true,
    );

    let (sk, pk, evk) = KeyGen::generate_mpc_key_pair(&mut backend, **parameters, rng);
    println!(
        "Party {} has generated the secret key, public key, and evaluation key.",
        party_id
    );

    let evaluator = Evaluator::new(evk);

    let test_num = 1;
    let mut public_a: Vec<Vec<u64>> = Vec::with_capacity(test_num);
    let mut public_b: Vec<u64> = Vec::new();

    println!(
        "double randoms cost {} ns,",
        backend.total_mul_triple_duration().as_nanos()
    );

    backend.init_z2k_triples_from_files();
    let a = 2;
    let b = 3;
    for _i in 0..test_num {
        let x = pk.encrypt(a, lwe_params, rng);
        let y = pk.encrypt(b, lwe_params, rng);

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
}
