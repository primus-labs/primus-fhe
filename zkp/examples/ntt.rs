use algebra::utils::Transcript;
use algebra::{transformation::AbstractNTT, NTTField, Polynomial};
use algebra::{BabyBear, BabyBearExetension};
use algebra::{DenseMultilinearExtension, Field};
use num_traits::One;
use pcs::multilinear::BrakedownPCS;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use sha2::Sha256;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;
use zkp::piop::ntt::{BatchNTTInstance, BitsOrder, NTTParams};
use zkp::piop::ntt::{NTTProof, NTTProver, NTTVerifier};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

type PolyFF = Polynomial<FF>;

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = DefaultFieldU32: denotes the ciphertext modulus in RLWE
const DIM_LWE: usize = 1024;
const LOG_DIM_RLWE: usize = 10;
const BITS_LEN: usize = 10;

/// Given an `index` of `len` bits, output a new index where the bits are reversed.
fn reverse_bits(index: usize, len: u32) -> usize {
    let mut tmp = index;
    let mut reverse_index = 0;
    let mut pow = 1 << (len - 1);
    for _ in 0..len {
        reverse_index += pow * (1 & tmp);
        pow >>= 1;
        tmp >>= 1;
    }
    reverse_index
}

/// Sort the array converting the index with reversed bits
/// array using little endian: 0  4  2  6  1  5  3  7
/// array using big endian   : 0  1  2  3  4  5  6  7
/// For the same elements, the bits of the index are reversed, e.g. 100(4) <-> 001(1) and (110)6 <-> (011)3
fn sort_array_with_reversed_bits<F: Clone + Copy>(input: &[F], log_n: u32) -> Vec<F> {
    assert_eq!(input.len(), (1 << log_n) as usize);
    let mut output = Vec::with_capacity(input.len());
    for i in 0..input.len() {
        let reverse_i = reverse_bits(i, log_n);
        output.push(input[reverse_i]);
    }
    output
}

/// Invoke the existing api to perform ntt transform and convert the bit-reversed order to normal order
/// In other words, the orders of input and output are both normal order.
/// ```plain
/// normal order:        0  1  2  3  4  5  6  7
///
/// bit-reversed order:  0  4  2  6  1  5  3  7
///                         -  ----  ----------
fn ntt_transform_normal_order<F: Field + NTTField>(log_n: u32, coeff: &[F]) -> Vec<F> {
    assert_eq!(coeff.len(), (1 << log_n) as usize);
    let poly = <Polynomial<F>>::from_slice(coeff);
    let ntt_form: Vec<_> = F::get_ntt_table(log_n).unwrap().transform(&poly).data();
    sort_array_with_reversed_bits(&ntt_form, log_n)
}

fn generate_single_instance<R: Rng + CryptoRng>(
    instances: &mut BatchNTTInstance<FF>,
    log_n: usize,
    rng: &mut R,
) {
    let coeff = PolyFF::random(1 << log_n, rng).data();
    let point = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff)
            .iter()
            .map(|x| FF::new(x.value()))
            .collect(),
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        coeff.iter().map(|x| FF::new(x.value())).collect(),
    ));
    instances.add_ntt_instance(&coeff, &point);
}

fn main() {
    let num_vars = LOG_DIM_RLWE;
    // let num_ntt = 5 as usize;
    let num_ntt = 2 * DIM_LWE * (1 + BITS_LEN);
    let log_n: usize = num_vars;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();

    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Arc::new(ntt_table);

    let mut rng = thread_rng();

    let mut ntt_instances = <BatchNTTInstance<FF>>::new(num_vars, &ntt_table);
    for _ in 0..num_ntt {
        generate_single_instance(&mut ntt_instances, log_n, &mut rng);
    }

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    let info = ntt_instances.info();
    println!("Prove {info}\n");

    // Parameters.
    let mut params = NTTParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let start = Instant::now();
    params.setup(&ntt_instances.info(), code_spec);
    println!("ntt setup time: {:?} ms", start.elapsed().as_millis());

    // Prover.
    let ntt_prover = NTTProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();

    let mut prover_trans = Transcript::<EF>::default();

    let start = Instant::now();
    let proof = ntt_prover.prove(
        &mut prover_trans,
        &params,
        &ntt_instances,
        BitsOrder::Normal,
    );
    println!("ntt proving time: {:?} ms", start.elapsed().as_millis());

    let proof_bytes = proof.to_bytes().unwrap();
    println!("ntt proof size: {:?} byts", proof_bytes.len());

    // Verifier.
    let ntt_verifier = NTTVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();

    let mut verifier_trans = Transcript::<EF>::default();

    let proof = NTTProof::from_bytes(&proof_bytes).unwrap();

    let start = Instant::now();
    let res = ntt_verifier.verify(
        &mut verifier_trans,
        &params,
        &ntt_instances.info(),
        &proof,
        BitsOrder::Normal,
    );

    println!("ntt verifying time: {:?} ms", start.elapsed().as_millis());
    assert!(res);
}
