use algebra::{transformation::AbstractNTT, NTTField, NTTPolynomial, Polynomial};
use algebra::{
    BabyBear, BabyBearExetension, Basis, DenseMultilinearExtension, Field, MultilinearExtension,
};
use itertools::izip;
use num_traits::One;
use pcs::utils::code::{ExpanderCode, ExpanderCodeSpec};
use rand::thread_rng;
use sha2::Sha256;
use std::rc::Rc;
use std::vec;
use zkp::piop::accumulator::AccumulatorSnarksOpt;
use zkp::piop::{
    accumulator::AccumulatorSnarks, AccumulatorIOP, AccumulatorInstance, AccumulatorWitness,
    DecomposedBitsInfo, NTTInstanceInfo, RlweCiphertext, RlweCiphertexts, RlweMultRgswInstance,
};

// field type
type FF = BabyBear;
type EF = BabyBearExetension;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

fn random_rlwe_ciphertext<F: Field, R>(rng: &mut R, num_vars: usize) -> RlweCiphertext<F>
where
    R: rand::Rng + rand::CryptoRng,
{
    RlweCiphertext {
        a: Rc::new(<DenseMultilinearExtension<F>>::random(num_vars, rng)),
        b: Rc::new(<DenseMultilinearExtension<F>>::random(num_vars, rng)),
    }
}

fn random_rlwe_ciphertexts<F: Field, R>(
    bits_len: usize,
    rng: &mut R,
    num_vars: usize,
) -> RlweCiphertexts<F>
where
    R: rand::Rng + rand::CryptoRng,
{
    RlweCiphertexts {
        a_bits: (0..bits_len)
            .map(|_| Rc::new(<DenseMultilinearExtension<F>>::random(num_vars, rng)))
            .collect(),
        b_bits: (0..bits_len)
            .map(|_| Rc::new(<DenseMultilinearExtension<F>>::random(num_vars, rng)))
            .collect(),
    }
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

fn generate_rlwe_mult_rgsw_instance<F: Field + NTTField>(
    num_vars: usize,
    input_rlwe: RlweCiphertext<F>,
    bits_rgsw_c_ntt: RlweCiphertexts<F>,
    bits_rgsw_f_ntt: RlweCiphertexts<F>,
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

    RlweMultRgswInstance::new(
        num_vars,
        bits_info,
        ntt_info,
        input_rlwe,
        bits_rlwe,
        bits_rlwe_ntt,
        bits_rgsw_c_ntt,
        bits_rgsw_f_ntt,
        output_rlwe_ntt,
        // &output_rlwe,
    )
}
// Perform d * ACC * RGSW(Zu)
// # Argument
// * input_d: scalar d = X^{-a_u} - 1 of the coefficient form
// * input_accumulator_ntt: ACC of the ntt form
// * input_rgsw_ntt: RGSW(Zu) of the ntt form
fn update_accumulator<F: Field + NTTField>(
    num_vars: usize,
    acc_ntt: RlweCiphertext<F>,
    d: DenseMultilinearExtension<F>,
    bits_rgsw_c_ntt: RlweCiphertexts<F>,
    bits_rgsw_f_ntt: RlweCiphertexts<F>,
    bits_info: &DecomposedBitsInfo<F>,
    ntt_info: &NTTInstanceInfo<F>,
) -> AccumulatorWitness<F> {
    // 1. Perform ntt transform on (x^{-a_u} - 1)
    let d_ntt = DenseMultilinearExtension::from_evaluations_vec(
        ntt_info.num_vars,
        ntt_transform_normal_order(ntt_info.num_vars as u32, &d.evaluations),
    );

    // 2. Perform point-multiplication to compute (x^{-a_u} - 1) * ACC
    let input_rlwe_ntt = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.num_vars,
            izip!(&d_ntt.evaluations, &acc_ntt.a.evaluations)
                .map(|(d_i, a_i)| *d_i * *a_i)
                .collect(),
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.num_vars,
            izip!(&d_ntt.evaluations, &acc_ntt.b.evaluations)
                .map(|(d_i, b_i)| *d_i * *b_i)
                .collect(),
        )),
    };

    // 3. Compute the RLWE of coefficient form as the input of the multiplication between RLWE and RGSW
    let input_rlwe = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.num_vars,
            ntt_inverse_transform_normal_order(
                ntt_info.num_vars as u32,
                &input_rlwe_ntt.a.evaluations,
            ),
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            ntt_info.num_vars,
            ntt_inverse_transform_normal_order(
                ntt_info.num_vars as u32,
                &input_rlwe_ntt.b.evaluations,
            ),
        )),
    };

    let rlwe_mult_rgsw = generate_rlwe_mult_rgsw_instance(
        num_vars,
        input_rlwe,
        bits_rgsw_c_ntt,
        bits_rgsw_f_ntt,
        bits_info,
        ntt_info,
    );

    AccumulatorWitness {
        acc_ntt: acc_ntt.clone(),
        d,
        d_ntt,
        input_rlwe_ntt,
        rlwe_mult_rgsw,
    }
}

fn generate_instance<F: Field + NTTField>(
    num_vars: usize,
    input: RlweCiphertext<F>,
    num_updations: usize,
    bits_info: &DecomposedBitsInfo<F>,
    ntt_info: &NTTInstanceInfo<F>,
) -> AccumulatorInstance<F> {
    let mut rng = rand::thread_rng();
    let mut updations = Vec::with_capacity(num_updations);

    let mut acc_ntt = RlweCiphertext::<F> {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            ntt_transform_normal_order(num_vars as u32, &input.a.evaluations),
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            ntt_transform_normal_order(num_vars as u32, &input.b.evaluations),
        )),
    };
    for _ in 0..num_updations {
        let d = DenseMultilinearExtension::random(num_vars, &mut rng);
        let bits_rgsw_c_ntt = random_rlwe_ciphertexts(bits_info.bits_len, &mut rng, num_vars);
        let bits_rgsw_f_ntt = random_rlwe_ciphertexts(bits_info.bits_len, &mut rng, num_vars);
        // perform ACC * d * RGSW
        let updation = update_accumulator(
            num_vars,
            acc_ntt.clone(),
            d,
            bits_rgsw_c_ntt,
            bits_rgsw_f_ntt,
            bits_info,
            ntt_info,
        );
        // perform ACC + ACC * d * RGSW
        acc_ntt = RlweCiphertext {
            a: Rc::new(acc_ntt.a.as_ref() + updation.rlwe_mult_rgsw.output_rlwe_ntt.a.as_ref()),
            b: Rc::new(acc_ntt.b.as_ref() + updation.rlwe_mult_rgsw.output_rlwe_ntt.b.as_ref()),
        };
        updations.push(updation);
    }

    let output = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            ntt_inverse_transform_normal_order(num_vars as u32, &acc_ntt.a.evaluations),
        )),
        b: Rc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            ntt_inverse_transform_normal_order(num_vars as u32, &acc_ntt.b.evaluations),
        )),
    };
    let output_ntt = acc_ntt;
    AccumulatorInstance::new(
        num_vars,
        num_updations,
        input,
        updations,
        output_ntt,
        output,
        bits_info,
        ntt_info,
    )
}

#[test]
fn test_random_accumulator() {
    // information used to decompose bits
    let base_len: usize = 2;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;
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

    let num_updations = 10;
    let input = random_rlwe_ciphertext(&mut thread_rng(), num_vars);
    let instance = generate_instance(num_vars, input, num_updations, &bits_info, &ntt_info);

    let info = instance.info();

    let (kit, recursive_proof) = AccumulatorIOP::<FF>::prove(&instance);

    let evals_at_r = instance.evaluate(&kit.randomness);
    let evals_at_u = instance.evaluate(&kit.u);

    let mut wrapper = kit.extract();
    let check = AccumulatorIOP::<FF>::verify(
        &mut wrapper,
        &evals_at_r,
        &evals_at_u,
        &info,
        &recursive_proof,
    );

    assert!(check);
}

#[test]
fn test_random_accumulator_extension_field() {
    // information used to decompose bits
    let base_len: usize = 2;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;
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

    let num_updations = 10;
    let input = random_rlwe_ciphertext(&mut thread_rng(), num_vars);
    let instance = generate_instance(num_vars, input, num_updations, &bits_info, &ntt_info);
    let instance_ef = instance.to_ef::<EF>();

    let info = instance_ef.info();

    let (kit, recursive_proof) = AccumulatorIOP::<EF>::prove(&instance_ef);

    let evals_at_r = instance.evaluate_ext(&kit.randomness);
    let evals_at_u = instance.evaluate_ext(&kit.u);

    let mut wrapper = kit.extract();
    let check = AccumulatorIOP::<EF>::verify(
        &mut wrapper,
        &evals_at_r,
        &evals_at_u,
        &info,
        &recursive_proof,
    );

    assert!(check);
}

#[test]
fn test_snarks() {
    // information used to decompose bits
    let base_len: usize = 2;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;
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

    let num_updations = 10;
    let input = random_rlwe_ciphertext(&mut thread_rng(), num_vars);
    let instance = generate_instance(num_vars, input, num_updations, &bits_info, &ntt_info);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <AccumulatorSnarks<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec,
    );
}

#[test]
fn test_snarks_with_lookup() {
    // information used to decompose bits
    let base_len: usize = 5;
    let base: FF = FF::new(1 << base_len);
    let bits_len = <Basis<FF>>::new(base_len as u32).decompose_len();
    let num_vars = 10;
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

    let num_updations = 10;
    let input = random_rlwe_ciphertext(&mut thread_rng(), num_vars);
    let instance = generate_instance(num_vars, input, num_updations, &bits_info, &ntt_info);

    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    <AccumulatorSnarksOpt<FF, EF>>::snarks::<Hash, ExpanderCode<FF>, ExpanderCodeSpec>(
        &instance, &code_spec, 2,
    );
}
