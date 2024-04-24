use algebra::Basis;
use algebra::{
    derive::{Field, Prime, NTT},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
// use protocol::bit_decomposition::{BitDecomposition, DecomposedBits};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{BitDecomposition, DecomposedBits};

#[derive(Field, Prime, NTT)]
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

    let d = DenseMultilinearExtension::from_evaluations_vec(num_vars, field_vec!(FF; 0, 1, 2, 3));
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
    let d_bits_verifier = vec![d_bits.clone()];

    let decomposed_bits_info = prover_key.info();
    let u = field_vec!(FF; 0, 0);
    let proof = BitDecomposition::prove(&prover_key, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
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
        DenseMultilinearExtension::from_evaluations_vec(num_vars, field_vec!(FF; 0, 1, 2, 3)),
        DenseMultilinearExtension::from_evaluations_vec(num_vars, field_vec!(FF; 0, 1, 2, 3)),
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

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for d_instance in &d_bits {
        decomposed_bits.add_decomposed_bits_instance(d_instance);
    }

    let decomposed_bits_info = decomposed_bits.info();

    let u: Vec<_> = (0..num_vars).map(|_| uniform.sample(&mut rng)).collect();
    let proof = BitDecomposition::prove(&decomposed_bits, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &d_bits, &u, &decomposed_bits_info));
}

#[test]
fn test_single_bit_decomposition() {
    let base_len: u32 = 4;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
    let num_vars = 10;

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let d = DenseMultilinearExtension::from_evaluations_vec(
        num_vars,
        (0..(1 << num_vars))
            .map(|_| uniform.sample(&mut rng))
            .collect(),
    );

    let d_bits_prover = d.get_decomposed_mles(base_len, bits_len);
    let d_verifier = vec![d];
    let d_bits_verifier = vec![d_bits_prover.clone()];

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    decomposed_bits.add_decomposed_bits_instance(&d_bits_prover);

    let decomposed_bits_info = decomposed_bits.info();

    let u: Vec<_> = (0..num_vars).map(|_| uniform.sample(&mut rng)).collect();
    let proof = BitDecomposition::prove(&decomposed_bits, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d_verifier, &d_bits_verifier, &u, &decomposed_bits_info));
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
        DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        ),
        DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        ),
        DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        ),
        DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            (0..(1 << num_vars))
                .map(|_| uniform.sample(&mut rng))
                .collect(),
        ),
    ];

    let d_bits = d
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for d_instance in &d_bits {
        decomposed_bits.add_decomposed_bits_instance(d_instance);
    }

    let decomposed_bits_info = decomposed_bits.info();

    let u: Vec<_> = (0..num_vars).map(|_| uniform.sample(&mut rng)).collect();
    let proof = BitDecomposition::prove(&decomposed_bits, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &d_bits, &u, &decomposed_bits_info));
}
