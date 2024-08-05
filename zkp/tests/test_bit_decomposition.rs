use algebra::utils::Transcript;
use algebra::Basis;
use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
// use protocol::bit_decomposition::{BitDecomposition, DecomposedBits};
use rand::prelude::*;
use rand_distr::Distribution;
use zkp::sumcheck::prover;
use std::rc::Rc;
use std::vec;
use zkp::piop::{BitDecomposition, DecomposedBits};

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

// field type
type FF = Fp32;

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
    prover_key.add_decomposed_bits_instance(&d_bits);

    let d_verifier = vec![d];
    let d_bits_verifier = vec![&d_bits];

    let decomposed_bits_info = prover_key.info();
    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let u = field_vec!(FF; 0, 0);
    let proof = BitDecomposition::prove(&mut prover_trans, &prover_key, &u);
    let subclaim = BitDecomposition::verifier(&mut verifier_trans,&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d_verifier, &d_bits_verifier, &u, &decomposed_bits_info));
}

#[test]
fn test_batch_trivial_bit_decomposition_base_2() {
    let base_len: u32 = 1;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = 2;
    let num_vars = 2;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
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
    let d_bits_ref: Vec<_> = d_bits.iter().collect();

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for d_instance in &d_bits {
        decomposed_bits.add_decomposed_bits_instance(d_instance);
    }

    let decomposed_bits_info = decomposed_bits.info();
    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans.get_vec_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans.get_vec_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let proof = BitDecomposition::prove(&mut prover_trans, &decomposed_bits, &prover_u);
    let subclaim = BitDecomposition::verifier(&mut verifier_trans, &proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &d_bits_ref, &verifier_u, &decomposed_bits_info));
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
    let d_verifier = vec![d];
    let d_bits_verifier = vec![&d_bits_prover];

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    decomposed_bits.add_decomposed_bits_instance(&d_bits_prover);

    let decomposed_bits_info = decomposed_bits.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans.get_vec_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans.get_vec_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let proof = BitDecomposition::prove(&mut prover_trans, &decomposed_bits, &prover_u);
    let subclaim = BitDecomposition::verifier(&mut verifier_trans, &proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d_verifier, &d_bits_verifier, &verifier_u, &decomposed_bits_info));
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
    let d_bits_ref: Vec<_> = d_bits.iter().collect();

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for d_instance in d_bits.iter() {
        decomposed_bits.add_decomposed_bits_instance(d_instance);
    }

    let decomposed_bits_info = decomposed_bits.info();

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    let prover_u = prover_trans.get_vec_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verifier_u = verifier_trans.get_vec_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let proof = BitDecomposition::prove(&mut prover_trans,&decomposed_bits, &prover_u);
    let subclaim = BitDecomposition::verifier(&mut verifier_trans, &proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &d_bits_ref, &verifier_u, &decomposed_bits_info));
}
