use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    Basis, DenseMultilinearExtension, Field, FieldUniformSampler,
};
use algebra::{transformation::AbstractNTT, NTTField, NTTPolynomial, Polynomial};
use itertools::izip;
use num_traits::One;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::piop::{
    DecomposedBitsInfo, NTTInstanceInfo, RlweCiphertext, RlweCiphertexts, RlweMultRgswIOP,
    RlweMultRgswInstance,
};

#[derive(Field, Prime, DecomposableField, FheField, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);

// field type
type FF = Fp32;

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

fn ntt_inverse_transform_normal_order<F: Field + NTTField>(log_n: u32, points: &[F]) -> Vec<F> {
    assert_eq!(points.len(), (1 << log_n) as usize);
    let reversed_points = sort_array_with_reversed_bits(points, log_n);
    let ntt_poly = <NTTPolynomial<F>>::from_slice(&reversed_points);
    F::get_ntt_table(log_n)
        .unwrap()
        .inverse_transform(&ntt_poly)
        .data()
}

/// This function DOES NOT implement the real functionality of multiplication between RLWE ciphertext and RGSW ciphertext
/// It is only used to generate the consistent instance for test.
///
/// # Arguments:
/// * input_rlwe: RLWE ciphertext of the coefficient form
/// * input_rgsw: RGSW ciphertext of the ntt form
/// * basis_info: information used to decompose bits
/// * ntt_info: information used to perform NTT
/// * randomness_ntt: randomness used to generate a single randomized NTT instance
fn gen_rlwe_mult_rgsw_instance<F: Field + NTTField>(
    input_rlwe: RlweCiphertext<F>,
    input_rgsw: (RlweCiphertexts<F>, RlweCiphertexts<F>),
    basis_info: &DecomposedBitsInfo<F>,
    ntt_info: &NTTInstanceInfo<F>,
    randomness_ntt: &[F],
) -> RlweMultRgswInstance<F> {
    // 1. Decompose the input of RLWE ciphertex
    let bits_rlwe = RlweCiphertexts {
        a_bits: input_rlwe
            .a
            .get_decomposed_mles(basis_info.base_len, basis_info.bits_len),
        b_bits: input_rlwe
            .b
            .get_decomposed_mles(basis_info.base_len, basis_info.bits_len),
    };
    let (bits_rgsw_c_ntt, bits_rgsw_f_ntt) = input_rgsw;

    // 2. Compute the ntt form of the decomposed bits
    let bits_rlwe_ntt = RlweCiphertexts {
        a_bits: bits_rlwe
            .a_bits
            .iter()
            .map(|bit| {
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    ntt_info.log_n,
                    ntt_transform_normal_order(ntt_info.log_n as u32, &bit.evaluations),
                ))
            })
            .collect(),
        b_bits: bits_rlwe
            .b_bits
            .iter()
            .map(|bit| {
                Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                    ntt_info.log_n,
                    ntt_transform_normal_order(ntt_info.log_n as u32, &bit.evaluations),
                ))
            })
            .collect(),
    };

    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rlwe_ntt.b_bits.len());
    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rgsw_c_ntt.a_bits.len());
    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rgsw_f_ntt.a_bits.len());

    // 3. Compute the output of ntt form with the RGSW ciphertext and the decomposed bits of ntt form
    let mut output_g_ntt = vec![F::zero(); 1 << ntt_info.log_n];
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

    let mut output_h_ntt = vec![F::zero(); 1 << ntt_info.log_n];
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

    // 4. Compute the output of coefficient form
    let output_rlwe = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.log_n,
            ntt_inverse_transform_normal_order(ntt_info.log_n as u32, &output_g_ntt),
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.log_n,
            ntt_inverse_transform_normal_order(ntt_info.log_n as u32, &output_h_ntt),
        )),
    };

    let output_rlwe_ntt = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.log_n,
            output_g_ntt,
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.log_n,
            output_h_ntt,
        )),
    };

    RlweMultRgswInstance::from(
        basis_info,
        ntt_info,
        randomness_ntt,
        &input_rlwe,
        &bits_rlwe,
        &bits_rlwe_ntt,
        &bits_rgsw_c_ntt,
        &bits_rgsw_f_ntt,
        &output_rlwe_ntt,
        &output_rlwe,
    )
}

#[test]
fn test_trivial_rlwe_mult_rgsw() {
    let mut rng = rand::thread_rng();
    let uniform = <FieldUniformSampler<FF>>::new();

    // information used to decompose bits
    let base_len: u32 = 2;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<FF>>::new(base_len).decompose_len() as u32;
    let num_vars = 10;
    let basis_info = DecomposedBitsInfo {
        base,
        base_len,
        bits_len,
        num_vars,
        num_instances: 2,
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
    let ntt_info = NTTInstanceInfo { log_n, ntt_table };

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

    let num_ntt_instance = (basis_info.bits_len << 1) + 2;
    let randomness_ntt = (0..num_ntt_instance)
        .map(|_| uniform.sample(&mut rng))
        .collect::<Vec<_>>();

    // generate all the witness required
    let instance = gen_rlwe_mult_rgsw_instance(
        input_rlwe,
        (bits_rgsw_c_ntt, bits_rgsw_f_ntt),
        &basis_info,
        &ntt_info,
        &randomness_ntt,
    );

    // check the consistency of the randomized NTT instance
    let ntt_points =
        ntt_transform_normal_order(log_n as u32, &instance.ntt_instance.coeffs.evaluations);
    assert_eq!(ntt_points, instance.ntt_instance.points.evaluations);

    let instance_info = instance.info();

    let u: Vec<_> = (0..num_vars).map(|_| uniform.sample(&mut rng)).collect();
    let proof = RlweMultRgswIOP::prove(&instance, &u);

    let subclaim = RlweMultRgswIOP::verify(&proof, &randomness_ntt, &u, &instance_info);
    assert!(subclaim.verify_subclaim(
        &u,
        &randomness_ntt,
        &instance.ntt_instance.coeffs,
        &instance.ntt_instance.points,
        &instance.input_rlwe,
        &instance.bits_rlwe,
        &instance.bits_rlwe_ntt,
        &instance.bits_rgsw_c_ntt,
        &instance.bits_rgsw_f_ntt,
        &instance.output_rlwe_ntt,
        &instance.output_rlwe,
        &instance_info
    ));
}
