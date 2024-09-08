use algebra::{transformation::AbstractNTT, NTTField, Polynomial};
use algebra::{
    utils::Transcript, AbstractExtensionField, DecomposableField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, MultilinearExtension,
};
use algebra::{BabyBear, BabyBearExetension, Basis, FieldUniformSampler};
use itertools::izip;
use num_traits::{One, Zero};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use rand::prelude::*;
use sha2::Sha256;
use std::vec;
use std::{rc::Rc, time::Instant};
use zkp::piop::{
    rlwe_mul_rgsw::RlweMultRgswSnarks, DecomposedBitsInfo, NTTInstanceInfo, RlweCiphertext,
    RlweCiphertexts, RlweMultRgswIOP, RlweMultRgswInstance,
};

type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

type PolyFF = Polynomial<FF>;

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = DefaultFieldU32: denotes the ciphertext modulus in RLWE
const DIM_LWE: usize = 1024;
const LOG_DIM_RLWE: usize = 10;
const LOG_B: usize = 2;

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

/// Invoke the existing api to perform ntt transform and convert the bit-reversed order to normal oder
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

fn generate_instance<F: Field + NTTField>(
    num_vars: usize,
    input_rlwe: RlweCiphertext<F>,
    input_rgsw: (RlweCiphertexts<F>, RlweCiphertexts<F>),
    bits_info: &DecomposedBitsInfo<F>,
    ntt_info: &NTTInstanceInfo<F>,
) -> RlweMultRgswInstance<F> {
    // 1. Decompose the input of RLWE ciphertex
    let bits_rlwe = RlweCiphertexts {
        a_bits: input_rlwe
            .a
            .get_decomposed_mles(bits_info.base_len, bits_info.bits_len),
        b_bits: input_rlwe
            .b
            .get_decomposed_mles(bits_info.base_len, bits_info.bits_len),
    };
    let (bits_rgsw_c_ntt, bits_rgsw_f_ntt) = input_rgsw;

    // 2. Compute the ntt form of the decomposed bits
    let bits_rlwe_ntt = RlweCiphertexts {
        a_bits: bits_rlwe
            .a_bits
            .iter()
            .map(|bit| {
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    num_vars,
                    ntt_transform_normal_order(num_vars as u32, &bit.evaluations),
                ))
            })
            .collect(),
        b_bits: bits_rlwe
            .b_bits
            .iter()
            .map(|bit| {
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    num_vars,
                    ntt_transform_normal_order(num_vars as u32, &bit.evaluations),
                ))
            })
            .collect(),
    };

    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rlwe_ntt.b_bits.len());
    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rgsw_c_ntt.a_bits.len());
    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rgsw_f_ntt.a_bits.len());

    // 3. Compute the output of ntt form with the RGSW ciphertext and the decomposed bits of ntt form
    let mut output_g_ntt = vec![F::zero(); 1 << num_vars];
    for (a, b, c, f) in izip!(
        &bits_rlwe_ntt.a_bits,
        &bits_rlwe_ntt.b_bits,
        &bits_rgsw_c_ntt.a_bits,
        &bits_rgsw_f_ntt.a_bits
    ) {
        output_g_ntt.iter_mut().enumerate().for_each(|(i, g_i)| {
            *g_i += (a.evaluations[i] * c.evaluations[i]) + (b.evaluations[i] * f.evaluations[i]);
        });
    }

    let mut output_h_ntt = vec![F::zero(); 1 << num_vars];
    for (a, b, c, f) in izip!(
        &bits_rlwe_ntt.a_bits,
        &bits_rlwe_ntt.b_bits,
        &bits_rgsw_c_ntt.b_bits,
        &bits_rgsw_f_ntt.b_bits
    ) {
        output_h_ntt.iter_mut().enumerate().for_each(|(i, h_i)| {
            *h_i += (a.evaluations[i] * c.evaluations[i]) + (b.evaluations[i] * f.evaluations[i]);
        });
    }

    let output_rlwe_ntt = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            output_g_ntt,
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            output_h_ntt,
        )),
    };

    RlweMultRgswInstance::from_slice(
        num_vars,
        bits_info,
        ntt_info,
        &input_rlwe,
        &bits_rlwe,
        &bits_rlwe_ntt,
        &bits_rgsw_c_ntt,
        &bits_rgsw_f_ntt,
        &output_rlwe_ntt,
    )
}

fn main()
{
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    // information used to decompose bits
    let base_len = LOG_B;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = LOG_DIM_RLWE;
    let bits_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 0,
    };

    // information used to perform NTT
    let log_n = num_vars;
    let m = 1 << (log_n + 1);
    let mut ntt_table = Vec::with_capacity(m as usize);
    let root = FF::get_ntt_table(log_n as u32).unwrap().root();
    let mut power = FF::one();
    for _ in 0..m {
        ntt_table.push(power);
        power *= root;
    }
    let ntt_table = Rc::new(ntt_table);
    let ntt_info = NTTInstanceInfo {
        num_vars,
        ntt_table,
        num_ntt: 0,
    };

    // generate random RGSW ciphertext = (bits_rgsw_c_ntt, bits_rgsw_f_ntt) \in RLWE' \times \RLWE'
    let mut bits_rgsw_c_ntt = <RlweCiphertexts<FF>>::new(bits_len as usize);
    let points: Vec<_> = (0..1 << num_vars)
        .map(|_| uniform.sample(&mut rng))
        .collect();
    let coeffs: Vec<_> = (0..1 << num_vars)
        .map(|_| uniform.sample(&mut rng))
        .collect();
    for _ in 0..bits_len {
        bits_rgsw_c_ntt.add_rlwe(
            DenseMultilinearExtension::from_evaluations_slice(log_n, &points),
            DenseMultilinearExtension::from_evaluations_slice(log_n, &points),
        );
    }

    let mut bits_rgsw_f_ntt = <RlweCiphertexts<FF>>::new(bits_len as usize);
    for _ in 0..bits_len {
        bits_rgsw_f_ntt.add_rlwe(
            DenseMultilinearExtension::from_evaluations_slice(log_n, &points),
            DenseMultilinearExtension::from_evaluations_slice(log_n, &points),
        );
    }

    // generate the random RLWE ciphertext
    let input_rlwe = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_slice(
            log_n, &coeffs,
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_slice(
            log_n, &coeffs,
        )),
    };

    // generate all the witness required
    let instance = generate_instance(
        num_vars,
        input_rlwe,
        (bits_rgsw_c_ntt, bits_rgsw_f_ntt),
        &bits_info,
        &ntt_info,
    );

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <RlweMultRgswSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}
