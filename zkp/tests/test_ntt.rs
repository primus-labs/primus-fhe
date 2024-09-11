use algebra::{transformation::AbstractNTT, NTTField, Polynomial};
use algebra::{
    BabyBear, BabyBearExetension, DecomposableField, DenseMultilinearExtension, Field,
    MultilinearExtension, NTTPolynomial,
};
use num_traits::{One, Zero};
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::prelude::*;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::ntt::ntt_bare::init_fourier_table;
use zkp::piop::ntt::{NTTInstances, NTTSnarks};
use zkp::piop::{NTTBareIOP, NTTInstance, NTTIOP};

// field type
type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;
type PolyFF = Polynomial<FF>;

fn obtain_fourier_matrix_oracle(log_n: u32) -> DenseMultilinearExtension<FF> {
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }

    let mut fourier_matrix = vec![FF::zero(); (1 << log_n) * (1 << log_n)];
    // In little endian, the index for F[i, j] is i + (j << dim)
    for i in 0..1 << log_n {
        for j in 0..1 << log_n {
            let idx_power = (2 * i + 1) * j % m;
            let idx_fourier = i + (j << log_n);
            fourier_matrix[idx_fourier as usize] = ntt_table[idx_power as usize];
        }
    }
    DenseMultilinearExtension::from_evaluations_vec((log_n << 1) as usize, fourier_matrix)
}

/// Given an `index` of `len` bits, output a new index where the bits are reversed.
fn reverse_bits(index: usize, len: u32) -> usize {
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
fn sort_array_with_reversed_bits<F: Clone + Copy>(input: &[F], log_n: u32) -> Vec<F> {
    assert_eq!(input.len(), (1 << log_n) as usize);
    let mut output = Vec::with_capacity(input.len());
    for i in 0..input.len() {
        let reverse_i = reverse_bits(i, log_n);
        output.push(input[reverse_i]);
    }
    output
}

/// Invoke the existing api to perform ntt transform and convert the bit-reversed order to normal order
/// In other words, the orders of input and output are both normal order.
/// ```plain
/// normal order:        0  1  2  3  4  5  6  7
///
/// bit-reversed order:  0  4  2  6  1  5  3  7
///                         -  ----  ----------
fn ntt_transform_normal_order<F: Field + NTTField>(log_n: u32, coeff: &[F]) -> Vec<F> {
    assert_eq!(coeff.len(), (1 << log_n) as usize);
    let poly = <Polynomial<F>>::from_slice(coeff);
    let ntt_form: Vec<_> = F::get_ntt_table(log_n).unwrap().transform(&poly).data();
    sort_array_with_reversed_bits(&ntt_form, log_n)
}

/// Invoke the existing api to perform ntt inverse transform and convert the bit-reversed order to normal order
/// In other words, the orders of input and output are both normal order.
fn ntt_inverse_transform_normal_order<F: Field + NTTField>(log_n: u32, points: &[F]) -> Vec<F> {
    assert_eq!(points.len(), (1 << log_n) as usize);
    let reversed_points = sort_array_with_reversed_bits(points, log_n);
    let ntt_poly = <NTTPolynomial<F>>::from_slice(&reversed_points);
    F::get_ntt_table(log_n)
        .unwrap()
        .inverse_transform(&ntt_poly)
        .data()
}

/// Construct the fourier matrix and then compute the matrix-vector product with the coefficients.
/// The output is in the normal order: f(w), f(w^3), f(w^5), ..., f(w^{2n-1})
fn naive_ntt_transform_normal_order(log_n: u32, coeff: &[FF]) -> Vec<FF> {
    assert_eq!(coeff.len(), (1 << log_n) as usize);
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }

    let mut fourier_matrix = vec![FF::zero(); (1 << log_n) * (1 << log_n)];
    // In little endian, the index for F[i, j] is i + (j << dim)
    for i in 0..1 << log_n {
        for j in 0..1 << log_n {
            let idx_power = (2 * i + 1) * j % m;
            let idx_fourier = i + (j << log_n);
            fourier_matrix[idx_fourier as usize] = ntt_table[idx_power as usize];
        }
    }

    let mut ntt_form = vec![FF::zero(); 1 << log_n];
    for i in 0..1 << log_n {
        for j in 0..1 << log_n {
            ntt_form[i] += coeff[j] * fourier_matrix[i + (j << log_n)];
        }
    }
    ntt_form
}

fn generate_single_instance<R: Rng + CryptoRng>(
    instances: &mut NTTInstances<FF>,
    log_n: usize,
    rng: &mut R,
) {
    let coeff = PolyFF::random(1 << log_n, rng).data();
    let point = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff)
            .iter()
            .map(|x| FF::new(x.value()))
            .collect(),
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        coeff.iter().map(|x| FF::new(x.value())).collect(),
    ));
    instances.add_ntt(&coeff, &point);
}

#[test]
fn test_reverse_bits() {
    assert_eq!(2, reverse_bits(4, 4));
}

#[test]
fn test_sort_array() {
    let log_n = 4;
    let a: Vec<_> = (0..1 << log_n).collect();
    let b = sort_array_with_reversed_bits(&a, log_n);
    let c = sort_array_with_reversed_bits(&b, log_n);
    assert_eq!(a, c);
    assert_ne!(a, b);
}

#[test]
fn test_ntt_transform_normal_order() {
    let log_n = 10;
    let coeff = PolyFF::random(1 << log_n, &mut thread_rng()).data();
    let points_naive = naive_ntt_transform_normal_order(log_n, &coeff);
    let points = ntt_transform_normal_order(log_n, &coeff);
    assert_eq!(points, points_naive);
}

#[test]
fn test_ntt_inverse_transform_normal_order() {
    let log_n = 10;
    let coeff = PolyFF::random(1 << log_n, &mut thread_rng()).data();
    let points = ntt_transform_normal_order(log_n, &coeff);
    let coeff_rec = ntt_inverse_transform_normal_order(log_n, &points);
    assert_eq!(coeff, coeff_rec);

    let points = PolyFF::random(1 << log_n, &mut thread_rng()).data();
    let coeff = ntt_inverse_transform_normal_order(log_n, &points);
    let points_rec = ntt_transform_normal_order(log_n, &coeff);
    assert_eq!(points, points_rec);
}

#[test]
fn test_ntt_bare_without_delegation() {
    let log_n: usize = 10;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Rc::new(ntt_table);

    let mut rng = thread_rng();
    let coeff = PolyFF::random(1 << log_n, &mut rng).data();
    let points = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff),
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, coeff,
    ));

    let ntt_instance = NTTInstance::from_slice(log_n, &ntt_table, &coeff, &points);
    let ntt_instance_info = ntt_instance.info();

    let kit = NTTBareIOP::prove(&ntt_instance);
    let evals_at_u = ntt_instance.points.evaluate(&kit.u);
    let evals_at_r = ntt_instance.coeffs.evaluate(&kit.randomness);

    let f_u = init_fourier_table(&kit.u, &ntt_instance.ntt_table);
    let f_delegation = f_u.evaluate(&kit.randomness);
    let f_oracle = obtain_fourier_matrix_oracle(log_n as u32);
    let point = [kit.u.clone(), kit.randomness.clone()].concat();
    assert_eq!(f_oracle.evaluate(&point), f_delegation);

    let mut wrapper = kit.extract();

    let check = NTTBareIOP::verify(&mut wrapper, evals_at_r, evals_at_u, &ntt_instance_info);
    assert!(check);
}

#[test]
fn test_ntt_bare_without_delegation_extension_field() {
    let log_n: usize = 10;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Rc::new(ntt_table);

    let mut rng = thread_rng();
    let coeff = PolyFF::random(1 << log_n, &mut rng).data();
    let points = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff),
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, coeff,
    ));

    let ntt_instance = NTTInstance::from_slice(log_n, &ntt_table, &coeff, &points);

    let instance_ef = ntt_instance.to_ef::<EF>();
    let ntt_instance_info = instance_ef.info();

    let kit = NTTBareIOP::<EF>::prove(&instance_ef);
    let evals_at_u = ntt_instance.points.evaluate_ext(&kit.u);
    let evals_at_r = ntt_instance.coeffs.evaluate_ext(&kit.randomness);

    let mut wrapper = kit.extract();

    let check = NTTBareIOP::<EF>::verify(&mut wrapper, evals_at_r, evals_at_u, &ntt_instance_info);
    assert!(check);
}

#[test]
fn test_ntt_with_delegation() {
    let log_n: usize = 10;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Rc::new(ntt_table);

    let mut rng = thread_rng();
    let coeff = PolyFF::random(1 << log_n, &mut rng).data();
    let points = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff),
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, coeff,
    ));

    let ntt_instance = NTTInstance::from_slice(log_n, &ntt_table, &coeff, &points);
    let ntt_instance_info = ntt_instance.info();

    let (kit, recursive_proof) = NTTIOP::prove(&ntt_instance);
    let evals_at_r = ntt_instance.coeffs.evaluate(&kit.randomness);
    let evals_at_u = ntt_instance.points.evaluate(&kit.u);

    let mut wrapper = kit.extract();

    let check = NTTIOP::verify(
        &mut wrapper,
        evals_at_r,
        evals_at_u,
        &ntt_instance_info,
        &recursive_proof,
    );
    assert!(check);
}

#[test]
fn test_ntt_with_delegation_extension_field() {
    let log_n: usize = 10;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Rc::new(ntt_table);

    let mut rng = thread_rng();
    let coeff = PolyFF::random(1 << log_n, &mut rng).data();
    let points = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n,
        ntt_transform_normal_order(log_n as u32, &coeff),
    ));
    let coeff = Rc::new(DenseMultilinearExtension::from_evaluations_vec(
        log_n, coeff,
    ));

    let ntt_instance = NTTInstance::from_slice(log_n, &ntt_table, &coeff, &points);

    let instance_ef = ntt_instance.to_ef::<EF>();
    let ntt_instance_info = instance_ef.info();

    let (kit, recursive_proof) = NTTIOP::prove(&instance_ef);
    let evals_at_r = ntt_instance.coeffs.evaluate_ext(&kit.randomness);
    let evals_at_u = ntt_instance.points.evaluate_ext(&kit.u);

    let mut wrapper = kit.extract();
    let check = NTTIOP::verify(
        &mut wrapper,
        evals_at_r,
        evals_at_u,
        &ntt_instance_info,
        &recursive_proof,
    );
    assert!(check);
}

#[test]
fn test_snarks() {
    let num_vars = 10;
    let num_ntt = 5;
    let log_n: usize = num_vars;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();

    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Rc::new(ntt_table);

    let mut rng = thread_rng();

    let mut ntt_instances = <NTTInstances<FF>>::new(num_vars, &ntt_table);
    for _ in 0..num_ntt {
        generate_single_instance(&mut ntt_instances, log_n, &mut rng);
    }

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    <NTTSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &ntt_instances,
        &code_spec,
    );
}
