use algebra::{
    derive::{DecomposableField, FheField, Field, Prime, NTT},
    utils::Transcript,
    Basis, DenseMultilinearExtensionBase, Field, FieldUniformSampler, MultilinearExtensionBase,
};
use algebra::{transformation::AbstractNTT, NTTField, NTTPolynomial, Polynomial};
use fhe_core::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
use itertools::izip;
use num_traits::One;
use rand_distr::Distribution;
use std::rc::Rc;
use std::vec;
use zkp::{
    piop::{
        AccumulatorIOP, AccumulatorInstance, AccumulatorWitness, DecomposedBitsInfo,
        NTTInstanceInfo, RlweCiphertext, RlweCiphertexts,
    },
    utils::gen_identity_evaluations,
};

#[derive(Field, DecomposableField, Prime, FheField, NTT)]
#[modulus = 132120577]
pub struct Fp32(u32);
// field type
type FF = DefaultFieldU32;
type EF = DefaultExtendsionFieldU32x4;

#[derive(Field, DecomposableField, Prime)]
#[modulus = 59]
pub struct Fq(u32);

fn random_rlwe_ciphertext<F: Field, R>(rng: &mut R, num_vars: usize) -> RlweCiphertext<F>
where
    R: rand::Rng + rand::CryptoRng,
{
    RlweCiphertext {
        a: Rc::new(<DenseMultilinearExtensionBase<F>>::random(num_vars, rng)),
        b: Rc::new(<DenseMultilinearExtensionBase<F>>::random(num_vars, rng)),
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
            .map(|_| Rc::new(<DenseMultilinearExtensionBase<F>>::random(num_vars, rng)))
            .collect(),
        b_bits: (0..bits_len)
            .map(|_| Rc::new(<DenseMultilinearExtensionBase<F>>::random(num_vars, rng)))
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

/// Invoke the existing api to perform ntt transform and convert the bit-reversed order to normal oder
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

// Perform d * ACC * RGSW(Zu)
// # Argument
// * input_d: scalar d = X^{-a_u} - 1 of the coefficient form
// * input_accumulator_ntt: ACC of the ntt form
// * input_rgsw_ntt: RGSW(Zu) of the ntt form
fn update_accumulator<F: Field + NTTField>(
    input_accumulator_ntt: &RlweCiphertext<F>,
    input_d: Rc<DenseMultilinearExtensionBase<F>>,
    input_rgsw_ntt: (RlweCiphertexts<F>, RlweCiphertexts<F>),
    basis_info: &DecomposedBitsInfo<F>,
    ntt_info: &NTTInstanceInfo<F>,
) -> AccumulatorWitness<F> {
    // 1. Perform ntt transform on (x^{-a_u} - 1)
    let input_d_ntt = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        ntt_info.log_n,
        ntt_transform_normal_order(ntt_info.log_n as u32, &input_d.evaluations),
    ));

    // 2. Perform point-multiplication to compute (x^{-a_u} - 1) * ACC
    let input_rlwe_ntt = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            ntt_info.log_n,
            izip!(
                &input_d_ntt.evaluations,
                &input_accumulator_ntt.a.evaluations
            )
            .map(|(d_i, a_i)| *d_i * *a_i)
            .collect(),
        )),
        b: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            ntt_info.log_n,
            izip!(
                &input_d_ntt.evaluations,
                &input_accumulator_ntt.b.evaluations
            )
            .map(|(d_i, b_i)| *d_i * *b_i)
            .collect(),
        )),
    };

    // 3. Compute the RLWE of coefficient form as the input of the multiplication between RLWE and RGSW
    let input_rlwe = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            ntt_info.log_n,
            ntt_inverse_transform_normal_order(
                ntt_info.log_n as u32,
                &input_rlwe_ntt.a.evaluations,
            ),
        )),
        b: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            ntt_info.log_n,
            ntt_inverse_transform_normal_order(
                ntt_info.log_n as u32,
                &input_rlwe_ntt.b.evaluations,
            ),
        )),
    };

    // 4. Decompose the input of RLWE ciphertex
    let bits_rlwe = RlweCiphertexts {
        a_bits: input_rlwe
            .a
            .get_decomposed_mles(basis_info.base_len, basis_info.bits_len),
        b_bits: input_rlwe
            .b
            .get_decomposed_mles(basis_info.base_len, basis_info.bits_len),
    };
    let (bits_rgsw_c_ntt, bits_rgsw_f_ntt) = input_rgsw_ntt;

    // 5. Compute the ntt form of the decomposed bits
    let bits_rlwe_ntt = RlweCiphertexts {
        a_bits: bits_rlwe
            .a_bits
            .iter()
            .map(|bit| {
                Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
                    ntt_info.log_n,
                    ntt_transform_normal_order(ntt_info.log_n as u32, &bit.evaluations),
                ))
            })
            .collect(),
        b_bits: bits_rlwe
            .b_bits
            .iter()
            .map(|bit| {
                Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
                    ntt_info.log_n,
                    ntt_transform_normal_order(ntt_info.log_n as u32, &bit.evaluations),
                ))
            })
            .collect(),
    };

    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rlwe_ntt.b_bits.len());
    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rgsw_c_ntt.a_bits.len());
    assert_eq!(bits_rlwe_ntt.a_bits.len(), bits_rgsw_f_ntt.a_bits.len());

    // 6. Compute the output of ntt form with the RGSW ciphertext and the decomposed bits of ntt form
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

    let output_rlwe_ntt = RlweCiphertext {
        a: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            ntt_info.log_n,
            output_g_ntt,
        )),
        b: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            ntt_info.log_n,
            output_h_ntt,
        )),
    };

    AccumulatorWitness {
        accumulator_ntt: input_accumulator_ntt.clone(),
        d: input_d.clone(),
        d_ntt: input_d_ntt,
        input_rlwe_ntt,
        input_rlwe,
        bits_rlwe,
        bits_rlwe_ntt,
        bits_rgsw_c_ntt,
        bits_rgsw_f_ntt,
        output_rlwe_ntt,
    }
}

#[test]
fn test_trivial_accumulator() {
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
        num_ntt: 1,
        log_n,
        ntt_table,
    };

    let mut accumulator = random_rlwe_ciphertext(&mut rng, num_vars);
    let mut accumulator_instance =
        <AccumulatorInstance<FF, EF>>::new(num_vars, &ntt_info, &basis_info);

    // number of updations in ACC
    let num_updations = 10;
    let mut witnesses = Vec::with_capacity(num_updations);
    let random_d: Vec<_> = (0..1 << num_vars)
        .map(|_| uniform.sample(&mut rng))
        .collect();

    // number of ntt in each updation
    let num_ntt_iter = ((bits_len << 1) + 3) as usize;
    let num_ntt = num_updations * num_ntt_iter;

    let mut prover_trans = Transcript::<FF>::new();
    let mut verifier_trans = Transcript::<FF>::new();
    // randomness used to combine all ntt instances
    let prover_randomness_ntt =
        prover_trans.get_vec_ext_field_challenge(b"randomize ntt instances", num_ntt);
    let verify_randomness_ntt =
        verifier_trans.get_vec_ext_field_challenge(b"randomize ntt instances", num_ntt);

    let num_sumcheck = num_updations * 2;
    // randomness used to combine all sumcheck protocols
    let prover_randomness_sumcheck = prover_trans.get_vec_ext_field_challenge(
        b"randomness used to combine all sumcheck protocols",
        num_sumcheck,
    );
    let verify_randomness_sumcheck = verifier_trans.get_vec_ext_field_challenge(
        b"randomness used to combine all sumcheck protocols",
        num_sumcheck,
    );

    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let verify_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);

    let identity_func_at_u = Rc::new(gen_identity_evaluations(&prover_u));

    // update accumulator for `num_updations` times
    for idx in 0..num_updations {
        let input_d = Rc::new(DenseMultilinearExtensionBase::from_evaluations_slice(
            num_vars, &random_d,
        ));
        let rgsw_ntt = (
            random_rlwe_ciphertexts(basis_info.bits_len as usize, &mut rng, num_vars),
            random_rlwe_ciphertexts(basis_info.bits_len as usize, &mut rng, num_vars),
        );
        let witness = update_accumulator(&accumulator, input_d, rgsw_ntt, &basis_info, &ntt_info);

        accumulator_instance.add_witness(
            &prover_randomness_ntt[idx * num_ntt_iter..(idx + 1) * num_ntt_iter],
            &prover_randomness_sumcheck[idx * 2..(idx + 1) * 2],
            &identity_func_at_u,
            &witness,
        );
        accumulator = RlweCiphertext {
            a: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
                num_vars,
                izip!(accumulator.a.iter(), witness.output_rlwe_ntt.a.iter())
                    .map(|(acc, x)| *acc + *x)
                    .collect(),
            )),
            b: Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
                num_vars,
                izip!(accumulator.b.iter(), witness.output_rlwe_ntt.b.iter())
                    .map(|(acc, x)| *acc + *x)
                    .collect(),
            )),
        };
        witnesses.push(witness);
    }

    let info = accumulator_instance.info();
    let proof =
        <AccumulatorIOP<FF, EF>>::prove(&mut prover_trans, &accumulator_instance, &prover_u);
    let subclaim = <AccumulatorIOP<FF, EF>>::verify(&mut verifier_trans, &proof, &verify_u, &info);
    assert!(subclaim.verify_subclaim(
        &verify_u,
        &verify_randomness_ntt,
        &verify_randomness_sumcheck,
        &accumulator_instance.ntt_instance.coeffs,
        &accumulator_instance.ntt_instance.points,
        &witnesses,
        &info,
    ));
}
