use algebra::utils::Transcript;
use algebra::{
    AbstractExtensionField, BabyBear, BabyBearExetension, Basis, ListOfProductsOfPolynomials,
};
use algebra::{DenseMultilinearExtension, Field, FieldUniformSampler};
use itertools::izip;
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
use std::vec;
use zkp::piop::{BitDecomposition, BitDecompositionSnarks, DecomposedBits};
use zkp::sumcheck::MLSumcheck;
use zkp::utils::{
    eval_identity_function, gen_identity_evaluations, print_statistic, verify_oracle_relation,
};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_single_trivial_bit_decomposition_base_2() {
    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len = 2;
    let num_vars = 2;

    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 1, 2, 3),
    ));
    let d_bits = vec![
        // 0th bit
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 1, 0, 1),
        )),
        // 1st bit
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, 1, 1),
        )),
    ];

    let mut prover_key = DecomposedBits::new(base, base_len, bits_len, num_vars);
    prover_key.add_decomposed_bits_instance(&d, &d_bits);
    let info = prover_key.info();

    let kit = BitDecomposition::prove(&prover_key);
    let evals = prover_key.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = BitDecomposition::verify(&wrapper, &evals, &info);
    assert!(check);
}

#[test]
fn test_batch_trivial_bit_decomposition_base_2() {
    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len = 2;
    let num_vars = 2;

    let d = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 1, 2, 3),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 1, 2, 3),
        )),
    ];
    let d_bits = vec![
        vec![
            // 0th bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 1, 0, 1),
            )),
            // 1st bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 0, 1, 1),
            )),
        ],
        vec![
            // 0th bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 1, 0, 1),
            )),
            // 1st bit
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                field_vec!(FF; 0, 0, 1, 1),
            )),
        ],
    ];

    let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for (d_val, d_bits) in izip!(d, d_bits) {
        instance.add_decomposed_bits_instance(&d_val, &d_bits);
    }

    let info = instance.info();

    let kit = BitDecomposition::prove(&instance);
    let evals = instance.evaluate(&kit.randomness);

    let wrapper = kit.extract();
    let check = BitDecomposition::verify(&wrapper, &evals, &info);
    assert!(check);
}

#[test]
fn test_single_bit_decomposition() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

    let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
    instance.add_decomposed_bits_instance(&d, &d_bits_prover);

    let info = instance.info();

    let sumcheck_kit = BitDecomposition::prove(&instance);
    let evals = instance.evaluate(&sumcheck_kit.randomness);

    let wrapper = sumcheck_kit.extract();
    let check = BitDecomposition::verify(&wrapper, &evals, &info);
    assert!(check);
}

#[test]
fn test_batch_bit_decomposition() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
    ];

    let d_bits: Vec<_> = d
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for (val, bits) in izip!(d, d_bits) {
        instance.add_decomposed_bits_instance(&val, &bits);
    }

    let info = instance.info();

    let sumcheck_kit = BitDecomposition::prove(&instance);
    let evals = instance.evaluate(&sumcheck_kit.randomness);

    let wrapper = sumcheck_kit.extract();
    let check = BitDecomposition::verify(&wrapper, &evals, &info);
    assert!(check);
}

#[test]
fn test_single_bit_decomposition_extension_field() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

    let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
    instance.add_decomposed_bits_instance(&d, &d_bits_prover);

    let instance_ef = instance.to_ef::<EF>();
    let info = instance_ef.info();

    let kit = BitDecomposition::<EF>::prove(&instance_ef);
    let evals = instance.evaluate_ext(&kit.randomness);

    let wrapper = kit.extract();
    let check = BitDecomposition::<EF>::verify(&wrapper, &evals, &info);
    assert!(check);
}

#[test]
fn test_snarks() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

    let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
    instance.add_decomposed_bits_instance(&d, &d_bits_prover);
    let instance_info = instance.info();
    let ef_zero = EF::from_base(FF::new(0));

    println!("Prove {instance_info}\n");
    // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
    let committed_poly = instance.generate_oracle();

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    // 1. Use PCS to commit the above polynomial.
    let start = Instant::now();
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
        committed_poly.num_vars,
        Some(code_spec),
    );
    let setup_time = start.elapsed().as_millis();

    let start = Instant::now();
    let (comm, comm_state) =
        BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(
            &pp,
            &committed_poly,
        );
    let commit_time = start.elapsed().as_millis();

    // 2. Prover generates the proof
    let prover_start = Instant::now();
    let mut iop_proof_size = 0;
    let mut prover_trans = Transcript::<EF>::new();
    // Convert the original instance into an instance defined over EF
    let instance_ef = instance.to_ef::<EF>();
    let instance_info = instance_ef.info();

    // 2.1 Generate the random point to instantiate the sumcheck protocol
    let prover_u = prover_trans.get_vec_challenge(
        b"random point used to instantiate sumcheck protocol",
        instance.num_vars,
    );
    let eq_at_u = Rc::new(gen_identity_evaluations(&prover_u));

    // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
    let mut sumcheck_poly = ListOfProductsOfPolynomials::<EF>::new(instance.num_vars);
    let claimed_sum = ef_zero;
    // randomness to combine sumcheck protocols
    let randomness = <BitDecomposition<EF>>::sample_coins(&mut prover_trans, &instance_ef);
    BitDecomposition::prove_as_subprotocol(&randomness, &mut sumcheck_poly, &instance_ef, &eq_at_u);
    let poly_info = sumcheck_poly.info();

    // 2.3 Generate proof of sumcheck protocol
    let (sumcheck_proof, sumcheck_state) =
        <MLSumcheck<EF>>::prove_as_subprotocol(&mut prover_trans, &sumcheck_poly)
            .expect("Proof generated in Addition In Zq");
    iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();
    let iop_prover_time = prover_start.elapsed().as_millis();

    // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
    let start = Instant::now();
    let evals = instance.evaluate_ext(&sumcheck_state.randomness);

    // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
    let mut requested_point = sumcheck_state.randomness.clone();
    requested_point.extend(&prover_trans.get_vec_challenge(
        b"random linear combination for evaluations of oracles",
        instance.log_num_oracles(),
    ));
    let oracle_eval = committed_poly.evaluate_ext(&requested_point);

    // 2.6 Generate the evaluation proof of the requested point
    let eval_proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp,
        &comm,
        &comm_state,
        &requested_point,
        &mut prover_trans,
    );
    let pcs_open_time = start.elapsed().as_millis();

    // 3. Verifier checks the proof
    let verifier_start = Instant::now();
    let mut verifier_trans = Transcript::<EF>::new();

    // 3.1 Generate the random point to instantiate the sumcheck protocol
    let verifier_u = verifier_trans.get_vec_challenge(
        b"random point used to instantiate sumcheck protocol",
        instance.num_vars,
    );

    // 3.2 Generate the randomness used to randomize all the sub-sumcheck protocols
    let randomness = verifier_trans.get_vec_challenge(
        b"randomness to combine sumcheck protocols",
        <BitDecomposition<EF>>::num_coins(&instance_info),
    );

    // 3.3 Check the proof of the sumcheck protocol
    let mut subclaim = <MLSumcheck<EF>>::verify_as_subprotocol(
        &mut verifier_trans,
        &poly_info,
        claimed_sum,
        &sumcheck_proof,
    )
    .expect("Verify the sumcheck proof generated in Bit Decomposition");
    let eq_at_u_r = eval_identity_function(&verifier_u, &subclaim.point);

    // 3.4 Check the evaluation over a random point of the polynomial proved in the sumcheck protocol using evaluations over these small oracles used in IOP
    let check_subcliam = BitDecomposition::<EF>::verify_as_subprotocol(
        &randomness,
        &mut subclaim,
        &evals,
        &instance_info,
        eq_at_u_r,
    );
    assert!(check_subcliam && subclaim.expected_evaluations == ef_zero);
    let iop_verifier_time = verifier_start.elapsed().as_millis();

    // 3.5 and also check the relation between these small oracles and the committed oracle
    let start = Instant::now();
    let mut pcs_proof_size = 0;
    let flatten_evals = evals.flatten();
    let oracle_randomness = verifier_trans.get_vec_challenge(
        b"random linear combination for evaluations of oracles",
        evals.log_num_oracles(),
    );
    let check_oracle = verify_oracle_relation(&flatten_evals, oracle_eval, &oracle_randomness);
    assert!(check_oracle);

    // 3.5 Check the evaluation of a random point over the committed oracle

    let check_pcs = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp,
        &comm,
        &requested_point,
        oracle_eval,
        &eval_proof,
        &mut verifier_trans,
    );
    assert!(check_pcs);
    let pcs_verifier_time = start.elapsed().as_millis();
    pcs_proof_size += bincode::serialize(&eval_proof).unwrap().len()
        + bincode::serialize(&flatten_evals).unwrap().len();

    print_statistic(
        iop_prover_time + pcs_open_time,
        iop_verifier_time + pcs_verifier_time,
        iop_proof_size + pcs_proof_size,
        iop_prover_time,
        iop_verifier_time,
        iop_proof_size,
        committed_poly.num_vars,
        instance.num_oracles(),
        instance.num_vars,
        setup_time,
        commit_time,
        pcs_open_time,
        pcs_verifier_time,
        pcs_proof_size,
    )
}

#[test]
fn test_snarks_interface() {
    let base_len = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    ));

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

    let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
    instance.add_decomposed_bits_instance(&d, &d_bits_prover);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <BitDecompositionSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}
