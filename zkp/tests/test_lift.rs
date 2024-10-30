use algebra::{
    derive::{DecomposableField, Field, Prime},
    utils::Transcript,
    BabyBear, BabyBearExetension, DenseMultilinearExtension, Field, FieldUniformSampler,
    SparsePolynomial,
};
use num_traits::{One, Zero};
use pcs::{
    multilinear::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
};
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::{
    lift::{LiftParams, LiftProof, LiftProver, LiftVerifier},
    BitDecompositionInstanceInfo, LiftIOP, LiftInstance,
};

#[derive(Field, DecomposableField)]
#[modulus = 8]
pub struct Fq(u32);

// type FF = BabyBear; // field type
// type EF = BabyBearExetension;
#[derive(Field, Prime, DecomposableField)]
#[modulus = 132120577]
pub struct Fp32(u32);

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

// a small and trivial example
// q = 8, Q = , N = 8
// (2N/q) * a(x) = N * k(x) + r(x)
// k(x) * (1-k(x)) = 0
// (r(x) + 1)(1 - 2k(x)) = s(x)
// \sum y C(u, y) * t(y) = s(u)

// a = (0, 3, 5, 7)
// 2a = (0, 6, 10, 14)
// C = (1, 0, 0, 0, 0, 0, 0, 0)
//     (0, 0, 0, 0, 0, 0, 1, 0)
//     (0, 0, -1, 0, 0, 0, 0, 0)
//     (0, 0, 0, 0, 0, 0, -1, 0)
// k = (0, 0, 1, 1)
// r = (0, 6, 2, 6)
// s = (1, 7, -3, -7) = (1, 7, 56, 52)
#[test]
fn test_trivial_zq_to_rq() {
    let q = FF::new(8);
    let dim_rlwe = FF::new(8);
    let base_len: usize = 1;
    let base: FF = FF::new(2);
    let num_vars = 3;
    let bits_len: usize = 3;

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        field_vec!(FF; 0, 3, 5, 7, 0, 3, 5, 7),
    ));

    let sparse_outputs = vec![
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(0, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(6, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(2, -FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(6, -FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(0, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(6, FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(2, -FF::one())],
        )),
        Rc::new(SparsePolynomial::from_evaluations_vec(
            num_vars,
            vec![(6, -FF::one())],
        )),
    ];

    let outputs = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 1, 0, 0, 0, 0, 0, 0, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, 0, 0, 0, 0, 1, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, FF::MODULUS_VALUE-1, 0, 0, 0, 0, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, 0, 0, 0, 0, FF::MODULUS_VALUE-1, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 1, 0, 0, 0, 0, 0, 0, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, 0, 0, 0, 0, 1, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, FF::MODULUS_VALUE-1, 0, 0, 0, 0, 0),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            field_vec!(FF; 0, 0, 0, 0, 0, 0, FF::MODULUS_VALUE-1, 0),
        )),
    ];

    let bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 0,
    };
    let instance = LiftInstance::new(
        num_vars,
        q,
        dim_rlwe,
        &input,
        &outputs,
        &sparse_outputs,
        &bits_info,
    );

    let info = instance.info();
    let mut lift_iop = LiftIOP::default();
    let mut prover_trans = Transcript::<FF>::new();

    lift_iop.generate_randomness(&mut prover_trans, &info);
    lift_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = lift_iop.prove(&mut prover_trans, &instance);
    let evals_at_r = instance.evaluate(&kit.randomness);
    let evals_at_u = instance.evaluate(&kit.u);

    let wrapper = kit.extract();

    let mut lift_iop = LiftIOP::default();
    let mut verifier_trans = Transcript::<FF>::new();

    lift_iop.generate_randomness(&mut verifier_trans, &info);
    lift_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = lift_iop.verify(
        &mut verifier_trans,
        &wrapper,
        &evals_at_r,
        &evals_at_u,
        &info,
    );

    assert!(check);
}

fn transform(
    num_vars: usize,
    input: FF,
    q: FF,
    dim_rlwe: FF,
) -> (DenseMultilinearExtension<FF>, SparsePolynomial<FF>) {
    let factor = (FF::one() + FF::one()) * dim_rlwe / q;
    let mapped_input = factor * input;
    let mut output = vec![FF::zero(); 1 << num_vars];
    let mut sparse_output = SparsePolynomial::new(num_vars);
    if mapped_input < dim_rlwe {
        let idx = mapped_input.value() as usize;
        output[idx] = FF::one();
        sparse_output.add_eval(idx, FF::one());
    } else {
        let idx = (mapped_input - dim_rlwe).value() as usize;
        output[idx] = -FF::one();
        sparse_output.add_eval(idx, -FF::one());
    }
    (
        DenseMultilinearExtension::from_evaluations_vec(num_vars, output),
        sparse_output,
    )
}

#[test]
fn test_random_zq_to_rq() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<Fq>>::new();

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 4;
    let q = FF::new(Fq::MODULUS_VALUE);
    let dim_rlwe = FF::new(1 << num_vars);

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..1 << num_vars)
            .map(|_| FF::new(uniform.sample(&mut rng).value()))
            .collect(),
    ));
    let mut outputs = Vec::with_capacity(1 << num_vars);
    let mut sparse_outputs = Vec::with_capacity(1 << num_vars);
    for x in input.iter() {
        let (output, sparse_output) = transform(num_vars, *x, q, dim_rlwe);
        outputs.push(Rc::new(output));
        sparse_outputs.push(Rc::new(sparse_output));
    }

    let bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: num_vars,
        num_vars,
        num_instances: 0,
    };

    let instance = LiftInstance::new(
        num_vars,
        q,
        dim_rlwe,
        &input,
        &outputs,
        &sparse_outputs,
        &bits_info,
    );

    let info = instance.info();

    let mut lift_iop = LiftIOP::default();
    let mut prover_trans = Transcript::<FF>::new();

    lift_iop.generate_randomness(&mut prover_trans, &info);
    lift_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = lift_iop.prove(&mut prover_trans, &instance);
    let evals_at_r = instance.evaluate(&kit.randomness);
    let evals_at_u = instance.evaluate(&kit.u);

    let wrapper = kit.extract();

    let mut lift_iop = LiftIOP::default();
    let mut verifier_trans = Transcript::<FF>::new();

    lift_iop.generate_randomness(&mut verifier_trans, &info);
    lift_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let (check, _) = lift_iop.verify(
        &mut verifier_trans,
        &wrapper,
        &evals_at_r,
        &evals_at_u,
        &info,
    );

    assert!(check);
}

#[test]
fn test_random_zq_to_rq_extension_field() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<Fq>>::new();

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 4;
    let q = FF::new(Fq::MODULUS_VALUE);
    let dim_rlwe = FF::new(1 << num_vars);

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..1 << num_vars)
            .map(|_| FF::new(uniform.sample(&mut rng).value()))
            .collect(),
    ));
    let mut outputs = Vec::with_capacity(1 << num_vars);
    let mut sparse_outputs = Vec::with_capacity(1 << num_vars);
    for x in input.iter() {
        let (output, sparse_output) = transform(num_vars, *x, q, dim_rlwe);
        outputs.push(Rc::new(output));
        sparse_outputs.push(Rc::new(sparse_output));
    }

    let bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: num_vars,
        num_vars,
        num_instances: 0,
    };

    let instance = LiftInstance::new(
        num_vars,
        q,
        dim_rlwe,
        &input,
        &outputs,
        &sparse_outputs,
        &bits_info,
    );

    let instance_ef = instance.to_ef::<EF>();

    let info = instance_ef.info();

    let mut lift_iop = LiftIOP::default();
    let mut prover_trans = Transcript::<EF>::new();

    lift_iop.generate_randomness(&mut prover_trans, &info);
    lift_iop.generate_randomness_for_eq_function(&mut prover_trans, &info);

    let kit = lift_iop.prove(&mut prover_trans, &instance_ef);

    let evals_at_r = instance.evaluate_ext(&kit.randomness);
    let evals_at_u = instance.evaluate_ext(&kit.u);

    let mut lift_iop = LiftIOP::default();
    let mut verifier_trans = Transcript::<EF>::new();

    lift_iop.generate_randomness(&mut verifier_trans, &info);
    lift_iop.generate_randomness_for_eq_function(&mut verifier_trans, &info);

    let wrapper = kit.extract();
    let (check, _) = lift_iop.verify(
        &mut verifier_trans,
        &wrapper,
        &evals_at_r,
        &evals_at_u,
        &info,
    );

    assert!(check);
}

#[test]
fn test_lift_snark() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<Fq>>::new();

    let base_len = 1;
    let base: FF = FF::new(1 << base_len);
    let num_vars = 4;
    let q = FF::new(Fq::MODULUS_VALUE);
    let dim_rlwe = FF::new(1 << num_vars);

    let input = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..1 << num_vars)
            .map(|_| FF::new(uniform.sample(&mut rng).value()))
            .collect(),
    ));
    let mut outputs = Vec::with_capacity(1 << num_vars);
    let mut sparse_outputs = Vec::with_capacity(1 << num_vars);
    for x in input.iter() {
        let (output, sparse_output) = transform(num_vars, *x, q, dim_rlwe);
        outputs.push(Rc::new(output));
        sparse_outputs.push(Rc::new(sparse_output));
    }

    let bits_info = BitDecompositionInstanceInfo {
        base,
        base_len,
        bits_len: num_vars,
        num_vars,
        num_instances: 0,
    };

    let instance = LiftInstance::new(
        num_vars,
        q,
        dim_rlwe,
        &input,
        &outputs,
        &sparse_outputs,
        &bits_info,
    );

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    // Parameters.
    let mut params = LiftParams::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    params.setup(&instance.info(), code_spec);

    // Prover.
    let floor_prover = LiftProver::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut prover_trans = Transcript::<EF>::default();

    let proof = floor_prover.prove(&mut prover_trans, &params, &instance);

    let proof_bytes = proof.to_bytes().unwrap();

    // Verifier.
    let floor_verifier = LiftVerifier::<
        FF,
        EF,
        ExpanderCodeSpec,
        BrakedownPCS<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>,
    >::default();
    let mut verifier_trans = Transcript::<EF>::default();

    let proof = LiftProof::from_bytes(&proof_bytes).unwrap();

    let res = floor_verifier.verify(&mut verifier_trans, &params, &instance.info(), &proof);

    assert!(res);
}
