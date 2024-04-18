use algebra::Basis;
use algebra::{
    derive::{Field, Prime, NTT},
    DenseMultilinearExtension, Field, FieldUniformSampler,
};
use protocol::bit_decomposition::{BitDecomposition, DecomposedBits};
use rand::prelude::*;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;

#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

// field type
type FF = Fp32;
type T = u32;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

#[test]
fn test_decompose() {
    const BITS: u32 = 2;
    const B: u32 = 1 << BITS;
    let basis = <Basis<Fp32>>::new(BITS);
    let rng = &mut thread_rng();

    let uniform = <FieldUniformSampler<FF>>::new();
    let a: FF = uniform.sample(rng);
    let decompose = a.decompose(basis);
    let compose = decompose
        .into_iter()
        .enumerate()
        .fold(FF::new(0), |acc, (i, d)| {
            acc + d.mul_scalar(B.pow(i as T) as T)
        });

    assert_eq!(compose, a);
}

fn get_decomposed_bits<F: Field> (
    base: F,
    base_bits: u32, // only support power-of-two base of length `base_bits`
    len_bits: u32,
    num_variables: usize,
    input: &Vec<F>, 
) -> DecomposedBits<F> {
    let basis = <Basis<F>>::new(base_bits);
    let mut input_bits = Vec::with_capacity(len_bits as usize);
    for _ in 0..len_bits {
        input_bits.push(Vec::with_capacity(1 << num_variables));
    }
    for val in input {
        let mut val_bits = val.decompose(basis);
        val_bits.truncate(len_bits as usize);
        for (index, &bit) in val_bits.iter().enumerate() {
            input_bits[index].push(bit);
        }
    }
    
    let decomposed_bits = input_bits
        .iter()
        .map(|bit| {
            Rc::new(DenseMultilinearExtension::from_evaluations_slice(num_variables, bit))
        }).collect();

    DecomposedBits {
        base,
        base_bits,
        len_bits,
        num_variables,
        decomposed_bits,
    }
}

#[test]
fn test_trivial_bit_decomposition_base_2() {
    let d = DenseMultilinearExtension::from_evaluations_vec(2, field_vec!(FF; 0, 1, 2, 3));
    let d_bits = vec![
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            2,
            field_vec!(FF; 0, 1, 0, 1),
        )),
        Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            2,
            field_vec!(FF; 0, 0, 1, 1),
        )),
    ];

    let prover_key = DecomposedBits {
        base: FF::new(2),
        base_bits: 1,
        len_bits: 2,
        num_variables: 2,
        decomposed_bits: d_bits,
    };

    let verifier_oracle = prover_key.decomposed_bits.iter().map(|bit| {
        Rc::clone(bit)
    }).collect();

    let decomposed_bits_info = prover_key.info();
    let u = field_vec!(FF; 0, 0);
    let proof = BitDecomposition::prove(&prover_key, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &verifier_oracle, &u, &decomposed_bits_info));
}

#[test]
fn test_bit_decomposition_base_4() {
    let base_bits: u32 = 2;
    let base: FF = FF::new(4);
    let num_variables = 4;
    let basis = <Basis<FF>>::new(base_bits);
    let len_bits: u32 = basis.decompose_len() as u32;
    
    let mut rng = thread_rng();
    let sampler = <FieldUniformSampler<FF>>::new();
    let d: Vec<FF> = (0..(1 << num_variables))
        .map(|_| sampler.sample(&mut rng))
        .collect();

    let decomposed_bits = get_decomposed_bits(base, base_bits, len_bits, num_variables, &d);
    let d = DenseMultilinearExtension::from_evaluations_vec(num_variables, d);

    let verifier_oracle = decomposed_bits.decomposed_bits.iter().map(|bit| {
        Rc::clone(bit)
    }).collect();
    let decomposed_bits_info = decomposed_bits.info();
    
    let u: Vec<_> = (0..num_variables)
        .map(|_| sampler.sample(&mut rng))
        .collect();
    let proof = BitDecomposition::prove(&decomposed_bits, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &verifier_oracle, &u, &decomposed_bits_info));
}
