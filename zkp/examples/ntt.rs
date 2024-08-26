use algebra::{transformation::AbstractNTT, NTTField, Polynomial};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension,
    DenseMultilinearExtensionBase, Field, ListOfProductsOfPolynomials, MultilinearExtension,
};
use fhe_core::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
use num_traits::{One, Zero};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::prelude::*;
use sha2::Sha256;
use std::vec;
use std::{rc::Rc, time::Instant};
use zkp::piop::{NTTBareIOP, NTTIOP};
use zkp::utils::{print_pcs_statistic, print_statistic};
use zkp::{
    piop::ntt::{NTTInstanceExt, NTTInstances},
    sumcheck::MLSumcheck,
};

type FF = DefaultFieldU32;
type EF = DefaultExtendsionFieldU32x4;
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

/// Invoke the existing api to perform ntt transform and convert the bit-reversed order to normal oder
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
    instances: &mut NTTInstances<FF>,
    log_n: usize,
    rng: &mut R,
) {
    let coeff = PolyFF::random(1 << log_n, rng).data();
    let point = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff)
            .iter()
            .map(|x| FF::new(x.value()))
            .collect(),
    ));
    let coeff = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        log_n,
        coeff.iter().map(|x| FF::new(x.value())).collect(),
    ));
    instances.add_ntt(coeff, point);
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
    let ntt_table = Rc::new(ntt_table);

    let mut rng = thread_rng();

    let mut ntt_instances = <NTTInstances<FF>>::new(num_vars, log_n, &ntt_table);
    for _ in 0..num_ntt {
        generate_single_instance(&mut ntt_instances, log_n, &mut rng);
    }
    let info = ntt_instances.info();
    println!("Prove {info}\n");

    let num_oracles_half = num_ntt;
    let num_vars_added_half = num_oracles_half.next_power_of_two().ilog2() as usize;

    // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
    let poly = ntt_instances.generate_oracle();

    // 1. Use PCS to commit the above polynomial.
    let start = Instant::now();
    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars + num_vars_added_half + 1,
        Some(code_spec),
    );
    let setup_time = start.elapsed().as_millis();

    let start = Instant::now();
    let (comm, state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly);
    let commit_time = start.elapsed().as_millis();

    // 2. Prover generates the proof
    let prover_start = Instant::now();
    let mut prover_trans = Transcript::<FF>::new();

    // 2.1 Generate the random point to instantiate the sumcheck protocol
    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point used to instantiate sumcheck protocol", log_n);

    // 2.[one more step] Prover generate the random ntt instance from all instances to be proved
    let instance = <NTTInstanceExt<FF, EF>>::from_base_instances(
        &mut prover_trans,
        log_n,
        &ntt_table,
        &ntt_instances,
    );
    let info = instance.info();

    // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
    // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
    let mut poly_sumcheck = <ListOfProductsOfPolynomials<FF, EF>>::new(num_vars);
    let mut claimed_sum = EF::from_base(FF::new(0));
    claimed_sum += <NTTBareIOP<FF, EF>>::random_poly(&mut poly_sumcheck, &instance, &prover_u);

    // 2.3 Generate proof of sumcheck protocol
    let (sumcheck_proof, sumcheck_state) =
        <MLSumcheck<FF, EF>>::prove(&mut prover_trans, &poly_sumcheck)
            .expect("Proof generated in NTT");

    // 2.[one more step] Prover recursive prove the evaluation of F(u, v)
    let recursive_proof =
        <NTTIOP<FF, EF>>::prove_recursive(&mut prover_trans, &instance, &prover_u, &sumcheck_state);
    let f_delegation = recursive_proof.delegation_claimed_sums[0];

    // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
    let coeff_evals = ntt_instances.compute_coeff_evals(&sumcheck_state.randomness);
    let point_evals = ntt_instances.compute_point_evals(&prover_u);

    // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
    let mut coeff_requested_point = sumcheck_state.randomness.clone();
    let mut point_requested_point = prover_u.clone();
    let point_randomness = prover_trans.get_vec_ext_field_challenge(
        b"random linear combination for evaluations of oracles",
        num_vars_added_half,
    );
    coeff_requested_point.extend(&point_randomness);
    point_requested_point.extend(&point_randomness);
    coeff_requested_point.push(EF::zero());
    point_requested_point.push(EF::one());

    let large_oracle_coeff_eval = poly.evaluate_ext(&coeff_requested_point);
    let large_oracle_point_eval = poly.evaluate_ext(&point_requested_point);

    // 2.6 Generate the evaluation proof of the requested point
    let start = Instant::now();
    let coeff_eval_proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp,
        &comm,
        &state,
        &coeff_requested_point,
        &mut prover_trans,
    );
    let point_eval_proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp,
        &comm,
        &state,
        &point_requested_point,
        &mut prover_trans,
    );
    let open_time = start.elapsed().as_millis();
    let prover_time = prover_start.elapsed().as_millis();

    // 3. Verifier checks the proof
    let verifier_start = Instant::now();
    let mut verifier_trans = Transcript::<FF>::new();

    // 3.1 Generate the random point to instantiate the sumcheck protocol
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point used to instantiate sumcheck protocol", log_n);

    // 3.2 Verifier samples random coints to generate the random ntt instance from all instances to be proved
    let random_coins = <NTTBareIOP<FF, EF>>::random_coin_ntt(&mut verifier_trans, &info);

    // 3.3 Check the proof of the sumcheck protocol (NTT Bare)
    let subclaim = <MLSumcheck<FF, EF>>::verify(
        &mut verifier_trans,
        &poly_sumcheck.info(),
        claimed_sum,
        &sumcheck_proof,
    )
    .expect("Verify the proof generated in NTT");

    // 3.4 Check the subclaim returned from the sumcheck protocol
    let check_subclaim = info.verify_subclaim(
        &coeff_evals,
        &point_evals,
        f_delegation,
        &random_coins,
        &subclaim,
        claimed_sum,
    );
    // Check the delegation of F(u, v) used in the above check
    let check_recursive = <NTTIOP<FF, EF>>::verify_recursive(
        &mut verifier_trans,
        &recursive_proof,
        &info,
        &verifier_u,
        &subclaim,
    );
    // Check the relation between the committed oracle and the smaller oracles used in IOP
    let point_randomness = verifier_trans.get_vec_ext_field_challenge::<EF>(
        b"random linear combination for evaluations of oracles",
        num_vars_added_half,
    );
    let num_zeros_padded_half = (1 << num_vars_added_half) - num_oracles_half;
    let padded_zeros = vec![EF::zero(); num_zeros_padded_half];
    let mut coeff_vec = coeff_evals.clone();
    coeff_vec.extend(&padded_zeros);
    let mut point_vec = point_evals.clone();
    point_vec.extend(&padded_zeros);
    let coeff_oracle =
        <DenseMultilinearExtension<FF, EF>>::from_evaluations_vec(num_vars_added_half, coeff_vec);
    let point_oracle =
        <DenseMultilinearExtension<FF, EF>>::from_evaluations_vec(num_vars_added_half, point_vec);
    let check_oracle = coeff_oracle.evaluate(&point_randomness) == large_oracle_coeff_eval
        && point_oracle.evaluate(&point_randomness) == large_oracle_point_eval;
    assert!(check_subclaim);
    assert!(check_recursive);
    assert!(check_oracle);

    // 3.5 Check the evaluation of a random point over the committed oracle
    let start = Instant::now();
    let check_pcs_coeff = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp,
        &comm,
        &coeff_requested_point,
        large_oracle_coeff_eval,
        &coeff_eval_proof,
        &mut verifier_trans,
    );
    let check_pcs_point = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp,
        &comm,
        &point_requested_point,
        large_oracle_point_eval,
        &point_eval_proof,
        &mut verifier_trans,
    );
    let pcs_verifier_time = start.elapsed().as_millis();
    assert!(check_pcs_coeff && check_pcs_point);
    let verifier_time = verifier_start.elapsed().as_millis();

    // Print statistic
    print_statistic(
        "Total",
        prover_time,
        verifier_time,
        bincode::serialize(&sumcheck_proof).unwrap().len()
            + bincode::serialize(&recursive_proof).unwrap().len()
            + bincode::serialize(&coeff_eval_proof).unwrap().len()
            + bincode::serialize(&point_eval_proof).unwrap().len(),
    );
    print_pcs_statistic(
        poly.num_vars,
        ntt_instances.num_oracles(),
        num_vars,
        setup_time,
        commit_time,
        open_time,
        pcs_verifier_time,
        bincode::serialize(&coeff_eval_proof).unwrap().len()
            + bincode::serialize(&point_eval_proof).unwrap().len(),
    );
    print_statistic(
        "IOP(Sumcheck)",
        prover_time - open_time,
        verifier_time - pcs_verifier_time,
        bincode::serialize(&sumcheck_proof).unwrap().len()
            + bincode::serialize(&recursive_proof).unwrap().len(),
    );
}
