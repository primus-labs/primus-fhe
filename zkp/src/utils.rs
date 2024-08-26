//! This module defines some useful utils that may invoked by piop.
use algebra::{utils::Transcript, AbstractExtensionField, DenseMultilinearExtension, Field};

/// Generate MLE of the ideneity function eq(u,x) for x \in \{0, 1\}^dim
pub fn gen_identity_evaluations<F: Field, EF: AbstractExtensionField<F>>(
    u: &[EF],
) -> DenseMultilinearExtension<F, EF> {
    let dim = u.len();
    let mut evaluations: Vec<_> = vec![EF::zero(); 1 << dim];
    evaluations[0] = EF::one();
    for i in 0..dim {
        // The index represents a point in {0,1}^`num_vars` in little endian form.
        // For example, `0b1011` represents `P(1,1,0,1)`
        let u_i_rev = u[dim - i - 1];
        for b in (0..(1 << i)).rev() {
            evaluations[(b << 1) + 1] = evaluations[b] * u_i_rev;
            evaluations[b << 1] = evaluations[b] * (EF::one() - u_i_rev);
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}

/// Evaluate eq(u, v) = \prod_i (u_i * v_i + (1 - u_i) * (1 - v_i))
pub fn eval_identity_function<F: Field, EF: AbstractExtensionField<F>>(u: &[EF], v: &[EF]) -> EF {
    assert_eq!(u.len(), v.len());
    let mut evaluation = EF::one();
    for (u_i, v_i) in u.iter().zip(v) {
        evaluation *= *u_i * *v_i + (EF::one() - *u_i) * (EF::one() - *v_i);
    }
    evaluation
}

/// Verify the relationship between the evaluations of these small oracles and the requested evaluation of the committed oracle
///
/// # Arguments:
/// * `evals`: vector consisting of all the evaluations of relevant MLEs. The arrangement is consistent to the vector returned in `compute_evals`.
/// * `oracle_eval`: the requested point reduced over the committed polynomial, which is the random linear combination of the smaller oracles used in IOP.
/// * `trans`: the transcript maintained by verifier
#[inline]
pub fn verify_oracle_relation<F: Field, EF: AbstractExtensionField<F>>(
    evals: &[EF],
    oracle_eval: EF,
    trans: &mut Transcript<F>,
) -> bool {
    let num_oracles = evals.len();
    let num_vars_added = num_oracles.next_power_of_two().ilog2() as usize;
    let randomness_oracles = trans.get_vec_ext_field_challenge::<EF>(
        b"random linear combination for evaluations of oracles",
        num_vars_added,
    );
    let eq_at_r = gen_identity_evaluations(&randomness_oracles);
    let randomized_eval = evals
        .iter()
        .zip(eq_at_r.iter())
        .fold(EF::zero(), |acc, (eval, coeff)| acc + *eval * *coeff);
    randomized_eval == oracle_eval
}

// #[inline]
// pub fn verify_oracle_partial_relation<F: Field, EF: AbstractExtensionField<F>>(
//     start: usize,
//     evals: &[EF],
//     oracle_eval: EF,
//     trans: &mut Transcript<F>,
// ) -> bool {

// }
/// Print statistic
pub fn print_statistic(
    label: &'static str,
    prover_time: u128,
    verifier_time: u128,
    proof_size: usize,
) {
    println!("\n=={label} Statistic==");
    println!("Prove Time: {:?} ms", prover_time);
    println!("Verifier Time: {:?} ms", verifier_time);
    println!("Proof Size: {:?} Bytes", proof_size);
}

/// Print statistic of PCS
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn print_pcs_statistic(
    committed_poly_num_vars: usize,
    num_oracles: usize,
    oracle_num_vars: usize,
    setup_time: u128,
    commit_time: u128,
    open_time: u128,
    verifier_time: u128,
    proof_size: usize,
) {
    println!("\n==PCS Statistic==");
    println!(
        "The committed polynomial is of {} variables,",
        committed_poly_num_vars
    );
    println!(
        "which consists of {} smaller oracles used in IOP, each of which is of {} variables.",
        num_oracles, oracle_num_vars
    );
    println!("Setup Time: {:?} ms", setup_time);
    println!("Commit Time: {:?} ms", commit_time);
    println!("Open Time: {:?} ms", open_time);
    println!("Verify Time: {:?} ms", verifier_time);
    println!("Proof Size: {:?} Bytes", proof_size);
}

#[cfg(test)]
mod test {
    use crate::utils::{eval_identity_function, gen_identity_evaluations};
    use algebra::{
        derive::{Field, Prime},
        BabyBearExetension, FieldUniformSampler, MultilinearExtension,
    };
    use rand::thread_rng;
    use rand_distr::Distribution;

    #[derive(Field, Prime)]
    #[modulus = 132120577]
    pub struct Fp32(u32);
    // field type
    type EF = BabyBearExetension;

    #[test]
    fn test_gen_identity_evaluations() {
        let sampler = <FieldUniformSampler<EF>>::new();
        let mut rng = thread_rng();
        let dim = 10;
        let u: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        let identity_at_u = gen_identity_evaluations(&u);

        let v: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        assert_eq!(eval_identity_function(&u, &v), identity_at_u.evaluate(&v));
    }
}
