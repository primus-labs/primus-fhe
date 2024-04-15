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

    // create a deep copy of d_bits for oracles used in verification
    let d_bits_verification = d_bits.iter().map(|x| x.as_ref().clone()).collect();

    let decomposed_bits = DecomposedBits {
        base: FF::new(2),
        base_bits: 1,
        len_bits: 2,
        num_variables: 2,
        decomposed_bits: d_bits,
    };
    let decomposed_bits_info = decomposed_bits.info();
    let u = field_vec!(FF; 0, 0);
    let proof = BitDecomposition::prove(&decomposed_bits, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &d_bits_verification, &u, &decomposed_bits_info));
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

    // decompose bits of every element in d
    let mut d_bits = Vec::with_capacity(len_bits as usize);
    for _ in 0..len_bits {
        d_bits.push(Vec::with_capacity(1 << num_variables));
    }
    for val in &d {
        let mut val_bits = val.decompose(basis);
        val_bits.truncate(len_bits as usize);
        for (index, &bit) in val_bits.iter().enumerate() {
            d_bits[index].push(bit);
        }
    }

    let d = DenseMultilinearExtension::from_evaluations_vec(num_variables, d);
    let decomposed_bits = d_bits
        .iter()
        .map(|bit| {
            Rc::new(DenseMultilinearExtension::from_evaluations_slice(
                num_variables,
                bit,
            ))
        })
        .collect();

    let d_bits_verification = d_bits
        .iter()
        .map(|bit| DenseMultilinearExtension::from_evaluations_slice(num_variables, bit))
        .collect();

    let decomposed_bits = DecomposedBits {
        base,
        base_bits,
        len_bits,
        num_variables,
        decomposed_bits,
    };
    let decomposed_bits_info = decomposed_bits.info();
    let u: Vec<_> = (0..num_variables)
        .map(|_| sampler.sample(&mut rng))
        .collect();
    let proof = BitDecomposition::prove(&decomposed_bits, &u);
    let subclaim = BitDecomposition::verifier(&proof, &decomposed_bits_info);
    assert!(subclaim.verify_subclaim(&d, &d_bits_verification, &u, &decomposed_bits_info));
}
