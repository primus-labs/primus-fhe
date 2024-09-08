use algebra::utils::Transcript;
use algebra::{
    AbstractExtensionField, BabyBear, BabyBearExetension, Basis, DenseMultilinearExtension, ListOfProductsOfPolynomials
};
use algebra::{DecomposableField, Field, FieldUniformSampler};
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
use zkp::piop::{BitDecomposition, BitDecompositionSnarks, DecomposedBits};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE s.t. N = 2^num_vars
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = BabyBear: denotes the ciphertext modulus in RLWE
const DIM_LWE: usize = 1024;
const LOG_DIM_RLWE: usize = 10;
const LOG_B: u32 = 2;

fn generate_instance<F: DecomposableField>(
    num_instances: usize,
    num_vars: usize,
    base_len: usize,
    base: F,
    bits_len: usize,
) -> DecomposedBits<F> {
    let mut rng = thread_rng();
    let uniform = <FieldUniformSampler<F>>::new();
    let d = (0..num_instances)
        .map(|_| {
            Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                (0..(1 << num_vars))
                    .map(|_| uniform.sample(&mut rng))
                    .collect(),
            ))
        })
        .collect::<Vec<_>>();

    let d_bits: Vec<_> = d
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();

    let mut decomposed_bits = DecomposedBits::new(base, base_len, bits_len, num_vars);
    for (val, bits) in izip!(&d, &d_bits) {
        decomposed_bits.add_decomposed_bits_instance(val, bits);
    }
    decomposed_bits
}
fn main() {
    let base_len = LOG_B as usize;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = LOG_DIM_RLWE;

    // Generate 2 * n = 2048 instances to be proved, each instance consisting of N = 2^num_vars values to be decomposed.
    let decomposed_bits = generate_instance::<FF>(2 * DIM_LWE, num_vars, base_len, base, bits_len);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);

    <BitDecompositionSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &decomposed_bits,
        &code_spec,
    );
}
