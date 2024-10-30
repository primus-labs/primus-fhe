//! This module defines some useful utils that may invoked by piop.
use std::rc::Rc;

use algebra::{AbstractExtensionField, DenseMultilinearExtension, Field, SparsePolynomial};
use itertools::izip;

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

/// Evaluate M(u, y) for y \in \{0, 1\}^dim where M is a sparse matrix.
/// To be more specific, each row of the matrix consists of only constant entries.
/// M(u, y) = \sum_{x,y}\in {0,1} eq(u, x) * M(x, y) = \sum_{x, y}\in Non-zero Set eq(u, x) * M(x, y)
pub fn gen_sparse_at_u<F: Field>(
    sparse_matrix: &[Rc<SparsePolynomial<F>>],
    u: &[F],
) -> DenseMultilinearExtension<F> {
    assert_eq!(sparse_matrix.len(), 1 << u.len());
    let eq_at_u = gen_identity_evaluations(u);

    assert!(!sparse_matrix.is_empty());
    let num_vars = sparse_matrix[0].num_vars;
    let mut evals = vec![F::zero(); 1 << num_vars];
    for (eq_u, row) in izip!(eq_at_u.iter(), sparse_matrix.iter()) {
        for (idx, val) in row.iter() {
            evals[*idx] += *eq_u * *val;
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(num_vars, evals)
}

/// Evaluate M(u, y) for y \in \{0, 1\}^dim where M is a sparse matrix.
/// To be more specific, each row of the matrix consists of only constant entries.

pub fn gen_sparse_at_u_to_ef<F: Field, EF: AbstractExtensionField<F>>(
    sparse_matrix: &[Rc<SparsePolynomial<F>>],
    u: &[EF],
) -> DenseMultilinearExtension<EF> {
    assert_eq!(sparse_matrix.len(), 1 << u.len());
    let eq_at_u = gen_identity_evaluations(u);

    assert!(!sparse_matrix.is_empty());
    let num_vars = sparse_matrix[0].num_vars;
    let mut evals = vec![EF::zero(); 1 << num_vars];
    for (eq_u, row) in izip!(eq_at_u.iter(), sparse_matrix.iter()) {
        for (idx, val) in row.iter() {
            evals[*idx] += *eq_u * *val;
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(num_vars, evals)
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
    let eq_at_r = gen_identity_evaluations(random_point);
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
#[allow(clippy::too_many_arguments)]
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

// credit@Plonky3
/// Batch multiplicative inverses with Montgomery's trick
/// This is Montgomery's trick. At a high level, we invert the product of the given field
/// elements, then derive the individual inverses from that via multiplication.
///
/// The usual Montgomery trick involves calculating an array of cumulative products,
/// resulting in a long dependency chain. To increase instruction-level parallelism, we
/// compute WIDTH separate cumulative product arrays that only meet at the end.
///
/// # Panics
/// Might panic if asserts or unwraps uncover a bug.
pub fn batch_inverse<F: Field>(x: &[F]) -> Vec<F> {
    // Higher WIDTH increases instruction-level parallelism, but too high a value will cause us
    // to run out of registers.
    const WIDTH: usize = 4;
    // JN note: WIDTH is 4. The code is specialized to this value and will need
    // modification if it is changed. I tried to make it more generic, but Rust's const
    // generics are not yet good enough.

    // Handle special cases. Paradoxically, below is repetitive but concise.
    // The branches should be very predictable.
    let n = x.len();
    if n == 0 {
        return Vec::new();
    } else if n == 1 {
        return vec![x[0].inv()];
    } else if n == 2 {
        let x01 = x[0] * x[1];
        let x01inv = x01.inv();
        return vec![x01inv * x[1], x01inv * x[0]];
    } else if n == 3 {
        let x01 = x[0] * x[1];
        let x012 = x01 * x[2];
        let x012inv = x012.inv();
        let x01inv = x012inv * x[2];
        return vec![x01inv * x[1], x01inv * x[0], x012inv * x01];
    }
    debug_assert!(n >= WIDTH);

    // Buf is reused for a few things to save allocations.
    // Fill buf with cumulative product of x, only taking every 4th value. Concretely, buf will
    // be [
    //   x[0], x[1], x[2], x[3],
    //   x[0] * x[4], x[1] * x[5], x[2] * x[6], x[3] * x[7],
    //   x[0] * x[4] * x[8], x[1] * x[5] * x[9], x[2] * x[6] * x[10], x[3] * x[7] * x[11],
    //   ...
    // ].
    // If n is not a multiple of WIDTH, the result is truncated from the end. For example,
    // for n == 5, we get [x[0], x[1], x[2], x[3], x[0] * x[4]].
    let mut buf: Vec<F> = Vec::with_capacity(n);
    // cumul_prod holds the last WIDTH elements of buf. This is redundant, but it's how we
    // convince LLVM to keep the values in the registers.
    let mut cumul_prod: [F; WIDTH] = x[..WIDTH].try_into().unwrap();
    buf.extend(cumul_prod);
    for (i, &xi) in x[WIDTH..].iter().enumerate() {
        cumul_prod[i % WIDTH] *= xi;
        buf.push(cumul_prod[i % WIDTH]);
    }
    debug_assert_eq!(buf.len(), n);

    let mut a_inv = {
        // This is where the four dependency chains meet.
        // Take the last four elements of buf and invert them all.
        let c01 = cumul_prod[0] * cumul_prod[1];
        let c23 = cumul_prod[2] * cumul_prod[3];
        let c0123 = c01 * c23;
        let c0123inv = c0123.inv();
        let c01inv = c0123inv * c23;
        let c23inv = c0123inv * c01;
        [
            c01inv * cumul_prod[1],
            c01inv * cumul_prod[0],
            c23inv * cumul_prod[3],
            c23inv * cumul_prod[2],
        ]
    };

    for i in (WIDTH..n).rev() {
        // buf[i - WIDTH] has not been written to by this loop, so it equals
        // x[i % WIDTH] * x[i % WIDTH + WIDTH] * ... * x[i - WIDTH].
        buf[i] = buf[i - WIDTH] * a_inv[i % WIDTH];
        // buf[i] now holds the inverse of x[i].
        a_inv[i % WIDTH] *= x[i];
    }
    for i in (0..WIDTH).rev() {
        buf[i] = a_inv[i];
    }

    for (&bi, &xi) in buf.iter().zip(x) {
        // Sanity check only.
        debug_assert_eq!(bi * xi, F::one());
    }

    buf
}

#[cfg(test)]
mod test {
    use crate::utils::{eval_identity_function, gen_identity_evaluations};
    use algebra::{
        derive::{Field, Prime},
        FieldUniformSampler,
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
