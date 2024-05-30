use algebra::{
    derive::{Field, Prime, NTT},
    Basis, DenseMultilinearExtension, Field, FieldUniformSampler, MultilinearExtension,
};
use algebra::{
    transformation::{AbstractNTT, MonomialNTT},
    NTTField, Polynomial,
};
use rand::prelude::*;
use rand_distr::Distribution;
use std::{mem::swap, rc::Rc};
use std::vec;
use zkp::piop::{NTTIOP, NTTInstance, NTTBareIOP};

#[derive(Field, Prime, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

#[derive(Field, Prime)]
#[modulus = 59]
pub struct Fq(u32);

// field type
type FF = Fp32;
type PolyFF = Polynomial<FF>;

macro_rules! field_vec {
    ($t:ty; $elem:expr; $n:expr)=>{
        vec![<$t>::new($elem);$n]
    };
    ($t:ty; $($x:expr),+ $(,)?) => {
        vec![$(<$t>::new($x)),+]
    }
}

fn obtain_fourier_matrix_oracle(log_n: u32)
-> DenseMultilinearExtension<FF>
{
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::try_minimal_primitive_root(m).unwrap();
    let mut power = FF::ONE;
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }

    let mut fourier_matrix = vec![FF::ZERO; (1 << log_n) * (1 << log_n)];
    // In little endian, the index for F[i, j] is i + (j << dim)
    for i in 0..1<<log_n {
        for j in 0..1<<log_n {
            let idx_power = (2 * i + 1) * j % m;
            let idx_fourier = i + (j << log_n);
            fourier_matrix[idx_fourier as usize] = ntt_table[idx_power as usize];
        }
    }
    DenseMultilinearExtension::from_evaluations_vec((log_n << 1) as usize, fourier_matrix)
}

/// Given an `index` of `len` bits, output a new index where the bits are reversed.
fn reverse_bits(index: usize, len: u32)
-> usize
{
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
fn sort_array_with_reversed_bits<F: Clone + Copy>(input: &[F], log_n: u32)
-> Vec<F>
{
    assert_eq!(input.len(), (1 << log_n) as usize);
    let mut output = Vec::with_capacity(input.len());
    for i in 0..input.len() {
        let reverse_i = reverse_bits(i, log_n);
        output.push(input[reverse_i]);
    }
    output
}

/// Invoke the existing api to perform ntt transform and convert the bit-reversed order to normal oder
/// ```plain
/// normal order:        0  1  2  3  4  5  6  7
///
/// bit-reversed order:  0  4  2  6  1  5  3  7
///                         -  ----  ----------
fn ntt_transform_normal_order<F: Field + NTTField>(log_n: u32, coeff: &[F])
-> Vec<F>
{
    assert_eq!(coeff.len(), (1 << log_n) as usize);
    let poly = <Polynomial<F>>::from_slice(coeff);
    let ntt_form: Vec<_> = F::get_ntt_table(log_n).unwrap().transform(&poly).data();
    sort_array_with_reversed_bits(&ntt_form, log_n)
}

/// Construct the fourier matrix and then compute the matrix-vector product with the coefficents.
/// The output is in the normal order: f(w), f(w^3), f(w^5), ..., f(w^{2n-1})
fn naive_ntt_transform_normal_order(log_n: u32, coeff: &[FF]) -> Vec<FF> {
    assert_eq!(coeff.len(), (1 << log_n) as usize);
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::try_minimal_primitive_root(m).unwrap();
    let mut power = FF::ONE;
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }

    let mut fourier_matrix = vec![FF::ZERO; (1 << log_n) * (1 << log_n)];
    // In little endian, the index for F[i, j] is i + (j << dim)
    for i in 0..1<<log_n {
        for j in 0..1<<log_n {
            let idx_power = (2 * i + 1) * j % m;
            let idx_fourier = i + (j << log_n);
            fourier_matrix[idx_fourier as usize] = ntt_table[idx_power as usize];
        }
    }

    let mut ntt_form = vec![FF::ZERO; 1 << log_n];
    for i in 0..1<<log_n {
        for j in 0..1<<log_n {
            ntt_form[i] += coeff[j] * fourier_matrix[i + (j << log_n)];
        }
    }
    ntt_form
}

#[test]
fn test_reverse_bits() {
    assert_eq!(2, reverse_bits(4, 4));
}

#[test]
fn test_sort_array() {
    let log_n = 4;
    let a: Vec<_> = (0..1<<log_n).map(|x| x).collect();
    let b = sort_array_with_reversed_bits(&a, log_n);
    let c = sort_array_with_reversed_bits(&b, log_n);
    assert_eq!(a, c);
    assert_ne!(a, b);
}

#[test]
fn test_ntt_transform_normal_order() {
    let log_n = 10;
    let coeff = PolyFF::random(1<<log_n, &mut thread_rng()).data();
    let points_naive = naive_ntt_transform_normal_order(log_n, &coeff);
    let points = ntt_transform_normal_order(log_n, &coeff);
    assert_eq!(points, points_naive);
}

#[test]
fn test_ntt_bare() {
    let log_n = 10;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::try_minimal_primitive_root(m).unwrap();
    let mut power = FF::ONE;
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let coeff = PolyFF::random(1<<log_n, &mut rng).data();
    let points = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, 
        ntt_transform_normal_order(log_n as u32, &coeff)
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, 
        coeff
    ));

    let ntt_instance = NTTInstance::from_slice(
        log_n, 
        &ntt_table, 
        &coeff, 
        &points, 
    );
    let ntt_instance_info = ntt_instance.info();

    let u: Vec<_> = (0..log_n).map(|_| uniform.sample(&mut rng)).collect();
    let proof = NTTBareIOP::prove(&ntt_instance, &u);
    let subclaim = NTTBareIOP::verifier(&proof, &ntt_instance_info);

    let fourier_matrix = Rc::new(obtain_fourier_matrix_oracle(log_n as u32));
    assert!(subclaim.verify_subcliam(&fourier_matrix, &points, &coeff, &u, &ntt_instance_info));
}


#[test]
fn test_ntt_sumcheck() {
    let log_n = 10;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::try_minimal_primitive_root(m).unwrap();
    let mut power = FF::ONE;
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }

    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();
    let coeff = PolyFF::random(1<<log_n, &mut rng).data();
    let points = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, 
        ntt_transform_normal_order(log_n as u32, &coeff)
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, 
        coeff
    ));

    let ntt_instance = NTTInstance::from_slice(
        log_n, 
        &ntt_table, 
        &coeff, 
        &points, 
    );
    let ntt_instance_info = ntt_instance.info();

    let u: Vec<_> = (0..log_n).map(|_| uniform.sample(&mut rng)).collect();
    let proof = NTTIOP::prove(&ntt_instance, &u);
    let subclaim = NTTIOP::verifier(&proof, &ntt_instance_info, &u);

    let fourier_matrix = Rc::new(obtain_fourier_matrix_oracle(log_n as u32));
    // assert!(subclaim.verify_subcliam(&fourier_matrix, &points, &coeff, &u, &ntt_instance_info));
    assert!(subclaim.verify_subcliam(&points, &coeff, &u, &ntt_instance_info));
}

#[test]
fn test_constant() 
{
    let f = DenseMultilinearExtension::from_evaluations_vec(0, vec![FF::ONE]);
    assert_eq!(f.evaluate(&[]), FF::ONE);
}