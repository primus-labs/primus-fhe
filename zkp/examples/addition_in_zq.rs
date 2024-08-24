use std::time::Instant;
use algebra::utils::Transcript;
use algebra::{
    derive::{DecomposableField, Field},
    Field, FieldUniformSampler, DecomposableField,
};
use algebra::{BabyBear, BabyBearExetension, Basis, DenseMultilinearExtensionBase};
use fhe_core::{DefaultExtendsionFieldU32x4, DefaultFieldU32};
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{ExpanderCode, ExpanderCodeSpec},
    PolynomialCommitmentScheme,
};
use num_traits::{One, Zero};
use rand::prelude::*;
use rand_distr::Distribution;
use sha2::Sha256;
use zkp::utils::verify_oracle_relation;
use std::rc::Rc;
use std::vec;
use zkp::piop::{addition_in_zq, AdditionInZq, AdditionInZqInstance};

type FF = DefaultFieldU32;
type EF = DefaultExtendsionFieldU32x4;
type Hash = Sha256;
const BASE_FIELD_BITS: usize = 31;

#[derive(Field, DecomposableField)]
#[modulus = 1024]
pub struct Fq(u32);

// # Parameters
// n = 1024: denotes the dimension of LWE
// N = 1024: denotes the dimension of ring in RLWE
// B = 2^3: denotes the basis used in the bit decomposition
// q = 1024: denotes the modulus in LWE
// Q = DefaultFieldU32: denotes the ciphertext modulus in RLWE
fn main()
{
    let mut rng = thread_rng();
    let uniform_fq = <FieldUniformSampler<Fq>>::new();
    let num_vars = 10;
    let q = FF::new(Fq::MODULUS_VALUE);
    let base_len: u32 = 3;
    let base: FF = FF::new(1 << base_len);
    let bits_len: u32 = <Basis<Fq>>::new(base_len).decompose_len() as u32;

    // Addition in Zq
    let a: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let b: Vec<_> = (0..(1 << num_vars))
        .map(|_| uniform_fq.sample(&mut rng))
        .collect();
    let c_k: Vec<_> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| {
            if x.value() + y.value() >= Fq::MODULUS_VALUE {
                (*x + *y, Fq::one())
            } else {
                (*x + *y, Fq::zero())
            }
        })
        .collect();

    let (c, k): (Vec<_>, Vec<_>) = c_k.iter().cloned().unzip();

    let abc = vec![
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            // Converted to Fp
            a.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            b.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
        Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
            num_vars,
            c.iter().map(|x: &Fq| FF::new(x.value())).collect(),
        )),
    ];

    let k = Rc::new(DenseMultilinearExtensionBase::from_evaluations_vec(
        num_vars,
        k.iter().map(|x: &Fq| FF::new(x.value())).collect(),
    ));

    // decompose bits of every element in a, b, c
    let abc_bits: Vec<_> = abc
        .iter()
        .map(|x| x.get_decomposed_mles(base_len, bits_len))
        .collect();
    let abc_bits_ref: Vec<_> = abc_bits.iter().collect();

    let abc_instance = AdditionInZqInstance::from_slice(&abc, &k, q, base, base_len, bits_len);
    let addition_info = abc_instance.info();
    let num_oracles = addition_info.num_oracles();
    let num_vars_added = num_oracles.next_power_of_two().ilog2() as usize;

    println!("Prove {addition_info}");
    println!("");
    // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
    let poly = abc_instance.generate_oracle();

    // 1. Use PCS to commit the above polynomial.
    let start = Instant::now();
    let code_spec = ExpanderCodeSpec::new(0.1195, 0.0248, 1.9, BASE_FIELD_BITS, 10);
    let pp = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::setup(num_vars + num_vars_added, Some(code_spec));
    let setup_time = start.elapsed().as_millis();
    
    let start = Instant::now();
    let (comm, state) = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::commit(&pp, &poly);
    let commit_time = start.elapsed().as_millis();

    // 2. Prover generates the proof
    let start = Instant::now();
    let mut prover_trans = Transcript::<FF>::new();
    let prover_u = prover_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let proof = <AdditionInZq<FF, EF>>::prove(&mut prover_trans, &abc_instance, &prover_u);
    let mut prover_time = start.elapsed().as_millis();

    // 3. Verifier checks the proof
    let start = Instant::now();
    let mut verifier_trans = Transcript::<FF>::new();
    let verifier_u = verifier_trans
        .get_vec_ext_field_challenge(b"random point to instantiate sumcheck protocol", num_vars);
    let subclaim = AdditionInZq::verify(
        &mut verifier_trans,
        &proof,
        &addition_info.decomposed_bits_info,
    );
    let mut verifier_time = start.elapsed().as_millis();

    // 4. Prover needs to compute all the requested evaluations over the random point returned from the sumcheck protocol.
    //    These evaluations will be reduced a new requested point over the committed polynomial.
    //    The requested point is composed of newly generated randomness to combine small oracles and the old random point reduced from the sumcheck protocol
    let start = Instant::now();
    let small_oracle_evals = subclaim.compute_evals(&abc, k.as_ref(), &abc_bits_ref, &addition_info);
    let mut requested_point = subclaim.sumcheck_point.clone();
    requested_point.extend(&prover_trans.get_vec_ext_field_challenge(b"random linear combination for evaluations of oracles", num_vars_added));
    prover_time += start.elapsed().as_millis();

    // 5. Prover then open the requested point of the committed polynomial
    let start = Instant::now();
    let large_oracle_eval = poly.evaluate_ext(&requested_point);
    let eval_proof = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::open(
        &pp, &comm, &state, &requested_point, &mut prover_trans);
    let open_time = start.elapsed().as_millis();

    // 6. Verify checks the subclaim returned in IOP
    //    Verifier first checks the relation of these evals evaluated from smaller oracles,
    //    and then check the relation between the committed oracle and these smaller oracles.
    let start = Instant::now();
    let check_iop = subclaim.verify_subclaim_pcs(q, &small_oracle_evals, &verifier_u, &addition_info)
        && verify_oracle_relation(&small_oracle_evals, large_oracle_eval, &mut verifier_trans);
    assert!(check_iop);
    verifier_time += start.elapsed().as_millis();
    
    // 7. Verify finally checks the evaluation proof of the requested point.
    let start = Instant::now();
    let check_pcs = BrakedownPCS::<FF, Hash, ExpanderCode<FF>, ExpanderCodeSpec, EF>::verify(
        &pp, &comm, &requested_point, large_oracle_eval, &eval_proof, &mut verifier_trans);
    let verifier_time_pcs = start.elapsed().as_millis();
    assert!(check_pcs);
    
    println!("==statistic==");
    println!("The committed polynomial is of {} variables,", poly.num_vars);
    println!("which consists of {} smaller oracles used in IOP, each of which is of {} variables", num_oracles, num_vars);
    println!("[pcs] setup time: {:?} ms", setup_time);
    println!("[pcs] commit time: {:?} ms", commit_time);
    println!("[pcs] open time: {:?} ms", open_time);
    println!("[pcs] verify time: {:?} ms", verifier_time_pcs);
    println!("[pcs] proof size: {:?} Bytes", bincode::serialize(&eval_proof).unwrap().len());
    println!("");
    println!("[iop] prove time: {:?} ms", prover_time);
    println!("[iop] verifier time: {:?} ms", verifier_time);
    println!("[iop] proof size: {:?} Bytes", bincode::serialize(&proof).unwrap().len());
}