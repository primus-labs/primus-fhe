use algebra::utils::Transcript;
use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    Field, FieldUniformSampler,
};
use algebra::{BabyBear, BabyBearExetension, Basis, DenseMultilinearExtensionBase};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
// use protocol::bit_decomposition::{BitDecomposition, DecomposedBits};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{BitDecomposition, DecomposedBits};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

fn main()
{
    let base_len: u32 = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
    let num_vars = 10;

    // Generate instances to be proved
    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = vec![
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
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
    let d_bits_ref: Vec<_> = d_bits.iter().collect();

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for d_instance in d_bits.iter() {
        decomposed_bits.add_decomposed_bits_instance(d_instance);
    }

    let decomposed_bits_info = decomposed_bits.info();
    let num_oracles = decomposed_bits.instances.len() * (decomposed_bits.bits_len as usize + 1);
    let num_vars_added = num_oracles.next_power_of_two().ilog2() as usize;

    // This is the polynomial to be committed for prover.
    let poly = decomposed_bits.gen_oracle(&d);

    // Use PCS to commit the above polynomial.
    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(num_vars + num_vars_added, Some(code_spec));
    let (comm, state) = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly);

    
    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();

    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let proof = <BitDecomposition<FF, EF>>::prove(&mut prover_trans, &decomposed_bits, &prover_u);
    let subclaim =
        <BitDecomposition<FF, EF>>::verify(&mut verifier_trans, &proof, &decomposed_bits_info);
    
    
    // the requested point is composed of newly generated randomness and the old random point reduced from the sumcheck protocol
    let mut prover_oracle_point = subclaim.point.clone();
    prover_oracle_point.extend(&prover_trans.get_vec_ext_field_challenge(b"random linear combination for evaluations of oracles", num_vars_added));
    let oracle_eval = poly.evaluate_ext(&prover_oracle_point);
    let eval_proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp, &comm, &state, &prover_oracle_point, &mut prover_trans);

    let prove_evals = subclaim.prove_subclaim(&d, &d_bits_ref, &decomposed_bits_info);
    
    let check_iop = subclaim.verify_subclaim_pcs(&prove_evals, &verifier_u, &decomposed_bits_info, oracle_eval, &mut verifier_trans);
    assert!(check_iop);
    let check_pcs = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp, &comm, &prover_oracle_point, oracle_eval, &eval_proof, &mut verifier_trans);
    assert!(check_pcs);
}