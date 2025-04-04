/// cargo run --package thfhe --example thfhe --release -- -n 3
///  cargo build --package thfhe --example thfhe --release
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
    // 参数 t
    #[arg(short = 'i')]
    i: u32,
}

fn main() {
    let args = Args::parse();
    //const NUM_PARTIES: u32 =args.n;
    let number_parties = args.n;
    let party_id = args.i;
    //let number_threshold = args.t;
    let number_threshold = (number_parties - 1) / 2;
    //const THRESHOLD: u32 = args.t;
    const BASE_PORT: u32 = 20500;
    thfhe(party_id, number_parties, number_threshold, BASE_PORT);
}

// struct Args {
//     /// 参数 n
//     #[arg(short = 'n')]
//     n: u32,
// }

// fn main() {
//     let args = Args::parse();
//     //const NUM_PARTIES: u32 =args.n;
//     let number_parties = args.n;
//     //let number_threshold = args.t;
//     let number_threshold = (number_parties - 1) / 2;
//     //const THRESHOLD: u32 = args.t;
//     const BASE_PORT: u32 = 20500;
//     // thfhe(party_id, number_parties, number_threshold, BASE_PORT);
//     let threads = (0..number_parties)
//         .map(|party_id| {
//             thread::spawn(move || thfhe(party_id, number_parties, number_threshold, BASE_PORT))
//         })
//         .collect::<Vec<_>>();

//     for handle in threads {
//         handle.join().unwrap();
//     }
// }

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
    println!(
        "Party {} had finished the double randoms with time {} ns,",
        party_id,
        backend.total_mul_triple_duration().as_nanos()
    );

    let (sk, pk, evk) = KeyGen::generate_mpc_key_pair(&mut backend, **parameters, rng);

    let evaluator = Evaluator::new(evk);

    let test_total_num = [1, 10, 100, 1000, 20000];
    // let mut public_a: Vec<Vec<u64>> = Vec::with_capacity(test_num);
    // let mut public_b: Vec<u64> = Vec::new();

    backend.init_z2k_triples_from_files();
    let a: u64 = 1;
    let b: u64 = 2;
    let x = pk.encrypt(a, lwe_params, rng);
    let y = pk.encrypt(b, lwe_params, rng);
    let res = evaluator.add(&x, &y);
    let public_a_single = backend.sends_slice_to_all_parties(Some(res.a()), res.a().len(), 0);
    let public_b_single =
        backend.sends_slice_to_all_parties(Some(&vec![res.b()]), vec![res.b()].len(), 0)[0];

    for test_num in test_total_num {
        let public_a = vec![public_a_single.clone(); test_num];
        let public_b = vec![public_b_single; test_num];

        if party_id <= threshold {
            let my_sk = sk.input_lwe_secret_key.as_ref();

            let (my_dd_res, (online_duration, offline_duration)) =
                distdec(&mut backend, rng, &public_a, &public_b, my_sk);
            println!(
                "Party {} had finished the {}-dd-online with time {} ns,",
                party_id,
                test_num,
                online_duration.as_nanos()
            );
            println!(
                "Party {} had finished the {}-dd-offline with time {} ns,",
                party_id,
                test_num,
                offline_duration.as_nanos()
            );

            if party_id == 0 {
                let my_dd_res: Vec<u64> = my_dd_res.unwrap();
                println!(
                    "(a + b )%4= {}, my party id: {}, my dd result: {:?}",
                    (a + b) % 4,
                    backend.party_id(),
                    my_dd_res[0] % 4
                );
            }
        }
    }
    println!(
        "Party {} had finished the program with time {:?}",
        party_id,
        start.elapsed()
    );
}
