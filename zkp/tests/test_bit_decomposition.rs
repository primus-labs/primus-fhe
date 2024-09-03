use algebra::{BabyBear, BabyBearExetension, Basis};
use algebra::{
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
use itertools::izip;
// use protocol::bit_decomposition::{BitDecomposition, DecomposedBits};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use std::rc::Rc;
use std::time::Instant;
use std::vec;
use zkp::piop::{BitDecomposition, DecomposedBits};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
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
    let base_len: u32 = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = 2;
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
    
    let (proof, state, poly_info) = BitDecomposition::prove(&prover_key);
    let evals = prover_key.evaluate(&state.randomness);
    
    let check = BitDecomposition::verify(&proof, &poly_info, &evals, &info);
    assert!(check);
}

#[test]
fn test_batch_trivial_bit_decomposition_base_2() {
    let base_len: u32 = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = 2;
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

    let (proof, state, poly_info) = BitDecomposition::prove(&instance);
    let evals = instance.evaluate(&state.randomness);
    
    let check = BitDecomposition::verify(&proof, &poly_info, &evals, &info);
    assert!(check);
}

#[test]
fn test_single_bit_decomposition() {
    let base_len: u32 = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
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

    let (proof, state, poly_info) = BitDecomposition::prove(&instance);
    let evals = instance.evaluate(&state.randomness);
    
    let check = BitDecomposition::verify(&proof, &poly_info, &evals, &info);
    assert!(check);
}


#[test]
fn test_batch_bit_decomposition() {
    let base_len: u32 = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
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

    let (proof, state, poly_info) = BitDecomposition::prove(&instance);
    let evals = instance.evaluate(&state.randomness);
    
    let check = BitDecomposition::verify(&proof, &poly_info, &evals, &info);
    assert!(check);
}

#[test]
fn test_single_bit_decomposition_extension_field() {

    let base_len: u32 = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
    let num_vars = 10;

    let mut rng = thread_rng();
    let w = EF::random(&mut rng);
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

    let (proof, state, poly_info) = BitDecomposition::<EF>::prove(&instance_ef);
    let evals = instance.evaluate_ext(&state.randomness);
    
    let check = BitDecomposition::<EF>::verify(&proof, &poly_info, &evals, &info);
    assert!(check);
}

// #[test]
// fn test_snarks()
// {
//     let base_len: u32 = 4;
//     let base: FF = FF::new(1 << base_len);
//     let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
//     let num_vars = 10;

//     let mut rng = thread_rng();
//     let uniform = <FieldUniformSampler<FF>>::new();
//     let d = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
//         num_vars,
//         (0..(1 << num_vars))
//             .map(|_| uniform.sample(&mut rng))
//             .collect(),
//     ));

//     let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);

//     let mut instance = DecomposedBits::new(base, base_len, bits_len, num_vars);
//     instance.add_decomposed_bits_instance(&d, &d_bits_prover);
//     let instance_info = instance.info();

//     println!("Prove {instance_info}\n");
//     // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
//     let poly = instance.generate_oracle();

//     let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
//     // 1. Use PCS to commit the above polynomial.
//     let start = Instant::now();
//     let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(
//         poly.num_vars,
//         Some(code_spec),
//     );
//     let setup_time = start.elapsed().as_millis();

//     let start = Instant::now();
//     let (comm, state) =
//         BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly);
//     let commit_time = start.elapsed().as_millis();
// }