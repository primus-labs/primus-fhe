use algebra::utils::Transcript;
use algebra::{BabyBear, BabyBearExetension, Basis, DenseMultilinearExtensionBase};
use algebra::{DecomposableField, Field, FieldUniformSampler};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::time::Instant;
use zkp::piop::{BitDecomposition, DecomposedBits};
use zkp::sumcheck::MLSumcheck;
use zkp::utils::{print_pcs_statistic, print_statistic, verify_oracle_relation};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE s.t. N = 2^num_vars
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = BabyBear: denotes the ciphertext modulus in RLWE
const DIM_LWE: usize = 1024;
const DIM_RLWE: usize = 1024;
const LOG_DIM_RLWE: usize = 10;
const B: usize = 1 << 3;
const LOG_B: u32 = 3;
const MODULUS_LWE: usize = 1024;

fn generate_instance<F: DecomposableField>(
    num_instances: usize,
    num_vars: usize,
    base_len: u32,
    base: F,
    bits_len: u32,
) -> (Vec<Rc<DenseMultilinearExtensionBase<F>>>, DecomposedBits<F>) {
    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<F>>::new();
    let d = (0..num_instances)
        .map(|_| {
            Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
                num_vars,
                (0..(1 << num_vars))
                    .map(|_| uniform.sample(&mut rng))
                    .collect(),
            ))
        })
        .collect::<Vec<_>>();

    let d_bits: Vec<_> = d
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for d_instance in d_bits.iter() {
        decomposed_bits.add_decomposed_bits_instance(d_instance);
    }
    (d, decomposed_bits)
}
fn main() {
    let base_len: u32 = LOG_B;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
    let num_vars = LOG_DIM_RLWE;

    // Generate 2 * n = 2048 instances to be proved, each instance consists of N = 2^num_vars values to be decomposed.
    let (d, decomposed_bits) =
        generate_instance::<FF>(2 * DIM_LWE, num_vars, base_len, base, bits_len);

    let decomposed_bits_info = decomposed_bits.info();
    // Compute the number of smaller oracles composing the large oracle to be committed = 2 * n * (log_B + 1) = 24576
    let num_oracles = decomposed_bits.num_oracles();
    let num_vars_added = num_oracles.next_power_of_two().ilog2() as usize;

    println!("Prove {decomposed_bits_info}");
    // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
    let poly = decomposed_bits.generate_oracle(&d);

    // 1. Use PCS to commit the above polynomial.
    let start = Instant::now();
    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        num_vars + num_vars_added,
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
    let prover_u = prover_trans.get_vec_ext_field_challenge(
        b"random point used to instantiate sumcheck protocol",
        num_vars,
    );

    // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
    let (poly_sumcheck, claimed_sum) =
        <BitDecomposition<FF, EF>>::poly_proved(&mut prover_trans, &decomposed_bits, &prover_u);

    // 2.3 Generate proof of sumcheck protocol
    let (sumcheck_proof, sumcheck_state) =
        <MLSumcheck<FF, EF>>::prove(&mut prover_trans, &poly_sumcheck)
            .expect("Proof generated in Bit Decomposition");

    // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
    let evals = decomposed_bits.compute_evals(&d, &sumcheck_state.randomness);

    // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
    let mut requested_point = sumcheck_state.randomness.clone();
    requested_point.extend(&prover_trans.get_vec_ext_field_challenge(
        b"random linear combination for evaluations of oracles",
        num_vars_added,
    ));
    let large_oracle_eval = poly.evaluate_ext(&requested_point);

    // 2.6 Generate the evaluation proof of the requested point
    let start = Instant::now();
    let eval_proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp,
        &comm,
        &state,
        &requested_point,
        &mut prover_trans,
    );
    let open_time = start.elapsed().as_millis();
    let prover_time = prover_start.elapsed().as_millis();

    // 3. Verifier checks the proof
    let verifier_start = Instant::now();
    let mut verifier_trans = Transcript::<FF>::new();
    // 3.1 Generate the random point to instantiate the sumcheck protocol
    let verifier_u = verifier_trans.get_vec_ext_field_challenge(
        b"random point used to instantiate sumcheck protocol",
        num_vars,
    );
    // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
    let randomness =
        <BitDecomposition<FF, EF>>::random_verified(&mut verifier_trans, &decomposed_bits_info);
    // 3.3 Check the proof of the sumcheck protocol
    let subclaim = <MLSumcheck<FF, EF>>::verify(
        &mut verifier_trans,
        &poly_sumcheck.info(),
        claimed_sum,
        &sumcheck_proof,
    )
    .expect("Verify the proof generated in Bit Decompositon");
    // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP,
    //     and also check the relation between these small oracles and the committed oracle
    let check_subcliam =
        decomposed_bits_info.verify_subclaim(&evals, &verifier_u, &randomness, &subclaim)
            && verify_oracle_relation(&evals, large_oracle_eval, &mut verifier_trans);
    // 3.5 Check the evaluation of a random point over the committed oracle
    let start = Instant::now();
    let check_pcs = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp,
        &comm,
        &requested_point,
        large_oracle_eval,
        &eval_proof,
        &mut verifier_trans,
    );
    let pcs_verifier_time = start.elapsed().as_millis();
    assert!(check_subcliam && check_pcs);
    let verifier_time = verifier_start.elapsed().as_millis();

    // Print statistic
    print_statistic(
        "Total",
        prover_time,
        verifier_time,
        bincode::serialize(&eval_proof).unwrap().len()
            + bincode::serialize(&sumcheck_proof).unwrap().len(),
    );
    print_pcs_statistic(
        poly.num_vars,
        num_oracles,
        num_vars,
        setup_time,
        commit_time,
        open_time,
        pcs_verifier_time,
        bincode::serialize(&eval_proof).unwrap().len(),
    );
    print_statistic(
        "IOP(Sumcheck)",
        prover_time - open_time,
        verifier_time - pcs_verifier_time,
        bincode::serialize(&sumcheck_proof).unwrap().len(),
    );
}
