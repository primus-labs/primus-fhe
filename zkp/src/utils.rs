//! This module defines some useful utils that may invoked by piop.
use algebra::{AbstractExtensionField, DenseMultilinearExtension, Field};

/// Generate MLE of the ideneity function eq(u,x) for x \in \{0, 1\}^dim
pub fn gen_identity_evaluations<F: Field>(u: &[F]) -> DenseMultilinearExtension<F> {
    let dim = u.len();
    let mut evaluations: Vec<_> = vec![F::zero(); 1 << dim];
    evaluations[0] = F::one();
    for i in 0..dim {
        // The index represents a point in {0,1}^`num_vars` in little endian form.
        // For example, `0b1011` represents `P(1,1,0,1)`
        let u_i_rev = u[dim - i - 1];
        for b in (0..(1 << i)).rev() {
            evaluations[(b << 1) + 1] = evaluations[b] * u_i_rev;
            evaluations[b << 1] = evaluations[b] * (F::one() - u_i_rev);
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(dim, evaluations)
}

/// Evaluate eq(u, v) = \prod_i (u_i * v_i + (1 - u_i) * (1 - v_i))
pub fn eval_identity_function<F: Field>(u: &[F], v: &[F]) -> F {
    assert_eq!(u.len(), v.len());
    let mut evaluation = F::one();
    for (u_i, v_i) in u.iter().zip(v) {
        evaluation *= *u_i * *v_i + (F::one() - *u_i) * (F::one() - *v_i);
    }
    evaluation
}

/// AddAssign<(EF, &'a DenseMultilinearExtension<F>)> for DenseMultilinearExtension<EF>
/// output += r * input
pub fn add_assign_ef<F: Field, EF: AbstractExtensionField<F>>(
    output: &mut DenseMultilinearExtension<EF>,
    r: &EF,
    input: &DenseMultilinearExtension<F>,
) {
    output
        .iter_mut()
        .zip(input.iter())
        .for_each(|(x, y)| *x += *r * *y);
}

/// Verify the relationship between the evaluations of these small oracles and the requested evaluation of the committed oracle
///
/// # Arguments:
/// * `evals`: vector consisting of all the evaluations of relevant MLEs. The arrangement is consistent to the vector returned in `compute_evals`.
/// * `oracle_eval`: the requested point reduced over the committed polynomial, which is the random linear combination of the smaller oracles used in IOP.
/// * `trans`: the transcript maintained by verifier
#[inline]
pub fn verify_oracle_relation<F: Field>(evals: &[F], oracle_eval: F, random_point: &[F]) -> bool {
    let eq_at_r = gen_identity_evaluations(&random_point);
    let randomized_eval = evals
        .iter()
        .zip(eq_at_r.iter())
        .fold(F::zero(), |acc, (eval, coeff)| acc + *eval * *coeff);
    randomized_eval == oracle_eval
}

/// Print statistic
///
/// # Arguments
/// `total_prover_time` - open time in PCS + prover time in IOP
/// `total_verifier_time` - verifier time in PCS + verifier time in IOP
/// `total_proof_size` - eval proof + IOP proof
/// `committed_poly_num_vars` - number of variables of the committed polynomical
/// `num_oracles` - number of small oracles composing the committed oracle
/// `setup_time` - setup time in PCS
/// `commit_time` - commit time in PCS
/// `open_time` - open time in PCS
/// `verifier_time` - verifier
pub fn print_statistic(
    // Total
    total_prover_time: u128,
    total_verifier_time: u128,
    total_proof_size: usize,
    // IOP
    iop_prover_time: u128,
    iop_verifier_time: u128,
    iop_proof_size: usize,
    // PCS statistic
    committed_poly_num_vars: usize,
    num_oracles: usize,
    oracle_num_vars: usize,
    setup_time: u128,
    commit_time: u128,
    pcs_open_time: u128,
    pcs_verifier_time: u128,
    pcs_proof_size: usize,
) {
    println!("\n==Total Statistic==");
    println!("Prove Time: {:?} ms", total_prover_time);
    println!("Verifier Time: {:?} ms", total_verifier_time);
    println!("Proof Size: {:?} Bytes", total_proof_size);

    println!("\n==IOP Statistic==");
    println!("Prove Time: {:?} ms", iop_prover_time);
    println!("Verifier Time: {:?} ms", iop_verifier_time);
    println!("Proof Size: {:?} Bytes", iop_proof_size);

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
    println!("Open Time: {:?} ms", pcs_open_time);
    println!("Verify Time: {:?} ms", pcs_verifier_time);
    println!("Proof Size: {:?} Bytes\n", pcs_proof_size);
}

#[cfg(test)]
mod test {
    use crate::utils::{eval_identity_function, gen_identity_evaluations};
    use algebra::{
        derive::{Field, Prime},
        FieldUniformSampler, MultilinearExtension,
    };
    use rand::thread_rng;
    use rand_distr::Distribution;

    #[derive(Field, Prime)]
    #[modulus = 132120577]
    pub struct Fp32(u32);
    // field type
    type FF = Fp32;

    #[test]
    fn test_gen_identity_evaluations() {
        let sampler = <FieldUniformSampler<FF>>::new();
        let mut rng = thread_rng();
        let dim = 10;
        let u: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        let identity_at_u = gen_identity_evaluations(&u);

        let v: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        assert_eq!(eval_identity_function(&u, &v), identity_at_u.evaluate(&v));
    }
}
