//! PIOP for NTT Bare without delegation
//! The algorithm is derived from Chap3.1 in zkCNN: https://eprint.iacr.org/2021/673
//! The prover wants to convince that Number Theoretic Transform (NTT) algorithm.
//! NTT is widely used for the multiplication of two polynomials in field.
//!
//! The goal of this IOP is to prove:
//!
//! The main idea of this IOP is to prove:
//! For y \in \{0, 1\}^N:
//!     $$a(y) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(y, x) }$$
//! where c represents the coefficients of a degree-{N-1} polynomial and a represents the evaulations at (ω^1, ω^3, ..., ω^{2N-1}),
//!
//! Here ω is the primitive 2N-th root of unity such that ω^{2N} = 1.
//! F is the standard Fourier matrix with only 2N distinct values and F(y, x) = ω^{(2Y+1)X} where Y and X are the field representations for the binary representations y and x, respectively.
//!
//! The LHS and RHS of the above equation are both MLE for y, so it can be reduced to check at a random point due to Schwartz-Zippel Lemma.
//! The remaining thing is to prove $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$ with the sumcheck protocol
//! where u is the random challenge from the verifier.
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::{MLSumcheck, ProofWrapper, SumcheckKit};
use algebra::{
    utils::Transcript, DenseMultilinearExtension, Field, ListOfProductsOfPolynomials,
    MultilinearExtension,
};
use serde::Serialize;
use std::marker::PhantomData;
use std::rc::Rc;

use super::{NTTInstance, NTTInstanceInfo};

/// IOP for NTT, i.e. $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
pub struct NTTBareIOP<F: Field>(PhantomData<F>);

/// Naive implementation for initializing F(u, x) in NTT, which helps readers to understand the following dynamic programming version (`init_fourier_table``).
/// The formula is derived from zkCNN (https://eprint.iacr.org/2021/673)
/// In NTT, the Fourier matrix is different since we choose these points: ω^1, ω^3, ..., ω^{2N-1}
/// Compared to the original induction, the main differences here are F(y, x)  = ω^{(2Y+1) * X} and Y = \sum_{i = 0} y_i * 2^i.
/// The latter one indicates that we use little-endian.
/// As a result, the equation (8) in zkCNN is = ω^X * \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) in this case.
///
/// # Arguments
/// * u: the random point
/// * ntt_table: It stores the NTT table: ω^0, ω^1, ..., ω^{2N - 1}
///
/// In order to delegate the computation F(u, v) to prover, we decompose the ω^X term into the grand product.
///
/// Hence, the final equation is = \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
pub fn naive_init_fourier_table<F: Field>(
    u: &[F],
    ntt_table: &[F],
) -> DenseMultilinearExtension<F> {
    let log_n = u.len();
    let m = ntt_table.len(); // m = 2n = 2 * (1 << dim)

    let mut evaluations = vec![F::one(); 1 << log_n];

    for (x, eval_at_x) in evaluations.iter_mut().enumerate() {
        for (i, &u_i) in u.iter().enumerate().take(log_n) {
            let idx = (1 << (i + 1)) * x % m;

            let x_i = (x >> i) & 1;
            let x_i_idx = (1 << i) * x_i;
            *eval_at_x *= ((F::one() - u_i) + u_i * ntt_table[idx]) * ntt_table[x_i_idx];
        }
    }

    DenseMultilinearExtension::from_evaluations_vec(log_n, evaluations)
}

/// Generate MLE for the Fourier function F(u, x) for x \in \{0, 1\}^dim where u is the random point.
/// Dynamic programming implementation for initializing F(u, x) in NTT (derived from zkCNN: https://eprint.iacr.org/2021/673)
/// `N` is the dimension of the vector used to represent the polynomial in NTT.
///
/// In NTT, the Fourier matrix is different since we choose these points: ω^1, ω^3, ..., ω^{2N-1}
/// Compared to the original induction, the main differences here are F(y, x)  = ω^{(2Y+1) * X} and Y = \sum_{i = 0} y_i * 2^i.
/// The latter one indicates that we use little-endian.
/// As a result, the equation (8) in zkCNN is = ω^X * \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X})
///
/// In order to delegate the computation F(u, v) to prover, we decompose the ω^X term into the grand product.
/// Hence, the final equation is = \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
/// * (This function is the dynamic programming version of the above function.)
///
/// # Arguments
/// * u: the random point
/// * ω: It stores the NTT table: ω^0, ω^1, ..., ω^{2N - 1}
pub fn init_fourier_table<F: Field>(u: &[F], ntt_table: &[F]) -> DenseMultilinearExtension<F> {
    let log_n = u.len(); // n = 1 << dim
    let m = ntt_table.len(); // m = 2n = 2 * (1 << dim)

    // It store the evaluations of all F(u, x) for x \in \{0, 1\}^dim.
    // Note that in our implementation, we use little endian form, so the index `0b1011`
    // represents the point `P(1,1,0,1)` in {0,1}^`dim`
    let mut evaluations: Vec<_> = vec![F::zero(); 1 << log_n];
    evaluations[0] = F::one();

    // * Compute \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
    // The reason why we update the table with u_i in reverse order is that
    // in round i, ω^{2^{i + 1} is the (M / (2^{i+1}))-th root of unity, e.g. i = dim - 1, ω^{2^{i + 1} is the 2-th root of unity.
    // Hence, we need to align this with the update method in dynamic programming.
    //
    // Note that the last term ω^{2^i * x_i} is indeed multiplied in the normal order, from x_0 to x_{log{n-1}}
    // since we actually iterate from the LSB to MSB  when updating the table from size 1, 2, 4, 8, ..., n in dynamic programming.
    for i in (0..log_n).rev() {
        // i starts from log_n - 1 and ends to 0
        let k = log_n - 1 - i;
        let last_table_size = 1 << k;

        for j in (0..1 << (k + 1)).rev() {
            // idx is to indicate the power ω^{2^{i + 1} * j} in ntt_table
            let idx = (1 << (i + 1)) * j % m;
            // bit is the most significant bit of j. If bit = 1, we need to multiply by ω^{2^k * 1}
            let bit = j >> k;
            if bit == 1 {
                evaluations[j] = evaluations[j % last_table_size]
                    * (F::one() - u[i] + u[i] * ntt_table[idx])
                    * ntt_table[last_table_size];
            }
            // If bit = 0, we do not need to multiply because ω^{2^k * 0} = 1
            else {
                evaluations[j] =
                    evaluations[j % last_table_size] * (F::one() - u[i] + u[i] * ntt_table[idx]);
            }
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(log_n, evaluations)
}

impl<F: Field + Serialize> NTTBareIOP<F> {
    /// Prove NTT instance without delegation
    pub fn prove(instance: &NTTInstance<F>) -> SumcheckKit<F> {
        let mut trans = Transcript::<F>::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let randomness = F::one();
        let mut claimed_sum = F::zero();
        Self::prove_as_subprotocol(randomness, &mut poly, &mut claimed_sum, instance, &u);
        // let evals_u = instance.points.evaluate(&u);

        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

        SumcheckKit {
            proof,
            info: poly.info(),
            claimed_sum,
            randomness: state.randomness,
            u,
        }
    }

    /// Add the sumcheck proving NTT into the polynomial
    pub fn prove_as_subprotocol(
        randomness: F,
        poly: &mut ListOfProductsOfPolynomials<F>,
        claimed_sum: &mut F,
        instance: &NTTInstance<F>,
        u: &[F],
    ) {
        let f_u = Rc::new(init_fourier_table(u, &instance.ntt_table));
        poly.add_product([Rc::clone(&f_u), Rc::clone(&instance.coeffs)], randomness);
        *claimed_sum += randomness * instance.points.evaluate(u);
    }

    /// Verify NTT instance without delegation
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: F,
        evals_at_u: F,
        info: &NTTInstanceInfo<F>,
    ) -> bool {
        let mut trans = Transcript::new();

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );

        let f_u = init_fourier_table(&u, &info.ntt_table);
        // randomness to combine sumcheck protocols
        let randomness = F::one();

        let mut subclaim = MLSumcheck::verify(
            &mut trans,
            &wrapper.info,
            wrapper.claimed_sum,
            &wrapper.proof,
        )
        .expect("fail to verify the sumcheck protocol");

        let f_delegation = f_u.evaluate(&subclaim.point);

        if !Self::verify_as_subprotocol(
            randomness,
            &mut subclaim,
            &mut wrapper.claimed_sum,
            evals_at_r,
            evals_at_u,
            f_delegation,
        ) {
            return false;
        }

        subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()
    }

    /// Verify the evaluation of the sumcheck proving NTT
    pub fn verify_as_subprotocol(
        randomness: F,
        subclaim: &mut SubClaim<F>,
        claimed_sum: &mut F,
        evals_at_r: F,
        evals_at_u: F,
        f_delegation: F,
    ) -> bool {
        subclaim.expected_evaluations -= evals_at_r * f_delegation * randomness;
        *claimed_sum -= evals_at_u * randomness;
        true
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        derive::{DecomposableField, FheField, Field, Prime, NTT},
        DenseMultilinearExtension, Field, FieldUniformSampler, MultilinearExtension, NTTField,
    };
    use num_traits::{One, Zero};
    use rand::thread_rng;
    use rand_distr::Distribution;

    use super::{init_fourier_table, naive_init_fourier_table};

    macro_rules! field_vec {
        ($t:ty; $elem:expr; $n:expr)=>{
            vec![<$t>::new($elem);$n]
        };
        ($t:ty; $($x:expr),+ $(,)?) => {
            vec![$(<$t>::new($x)),+]
        }
    }

    #[derive(Field, DecomposableField, FheField, Prime, NTT)]
    #[modulus = 132120577]
    pub struct Fp32(u32);
    // field type
    type FF = Fp32;

    #[test]
    fn test_naive_init_fourier_matrix() {
        let dim = 2;
        let m = 1 << (dim + 1); // M = 2N = 2 * (1 << dim)
        let u = field_vec!(FF; 1, 1);
        let v = field_vec!(FF; 0, 1);

        let mut u_v = Vec::with_capacity(dim << 1);
        u_v.extend(&u);
        u_v.extend(&v);

        // root is the M-th root of unity
        let root = FF::try_minimal_primitive_root(m).unwrap();

        let mut fourier_matrix: Vec<_> = (0..(1 << dim) * (1 << dim)).map(|_| FF::zero()).collect();
        let mut ntt_table = Vec::with_capacity(m as usize);

        let mut power = FF::one();
        for _ in 0..m {
            ntt_table.push(power);
            power *= root;
        }

        // In little endian, the index for F[i, j] is i + (j << dim)
        for i in 0..1 << dim {
            for j in 0..1 << dim {
                let idx_power = (2 * i + 1) * j % m;
                let idx_fourier = i + (j << dim);
                fourier_matrix[idx_fourier as usize] = ntt_table[idx_power as usize];
            }
        }

        let fourier_mle = DenseMultilinearExtension::from_evaluations_vec(dim << 1, fourier_matrix);
        // It includes the evaluations of f(u, x) for x \in \{0, 1\}^N
        let partial_fourier_mle = naive_init_fourier_table(&u, &ntt_table);

        assert_eq!(fourier_mle.evaluate(&u_v), partial_fourier_mle.evaluate(&v));
    }

    #[test]
    fn test_init_fourier_matrix() {
        let sampler = <FieldUniformSampler<FF>>::new();
        let mut rng = thread_rng();

        let dim = 10;
        let m = 1 << (dim + 1); // M = 2N = 2 * (1 << dim)
        let u: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();
        let v: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        let mut u_v: Vec<_> = Vec::with_capacity(dim << 1);
        u_v.extend(&u);
        u_v.extend(&v);

        // root is the M-th root of unity
        let root = FF::try_minimal_primitive_root(m).unwrap();

        let mut fourier_matrix: Vec<_> = (0..(1 << dim) * (1 << dim)).map(|_| FF::zero()).collect();
        let mut ntt_table = Vec::with_capacity(m as usize);

        let mut power = FF::one();
        for _ in 0..m {
            ntt_table.push(power);
            power *= root;
        }

        // In little endian, the index for F[i, j] is i + (j << dim)
        for i in 0..1 << dim {
            for j in 0..1 << dim {
                let idx_power = (2 * i + 1) * j % m;
                let idx_fourier = i + (j << dim);
                fourier_matrix[idx_fourier as usize] = ntt_table[idx_power as usize];
            }
        }

        let fourier_mle = DenseMultilinearExtension::from_evaluations_vec(dim << 1, fourier_matrix);
        // It includes the evaluations of f(u, x) for x \in \{0, 1\}^N
        let partial_fourier_mle = &init_fourier_table(&u, &ntt_table);

        assert_eq!(fourier_mle.evaluate(&u_v), partial_fourier_mle.evaluate(&v));
    }
}
