//! PIOP for NTT with delegation
//! The algorithm is derived from Chap3.1 in zkCNN: https://eprint.iacr.org/2021/673
//! The prover wants to convince that Number Theoretic Transform (NTT) algorithm.
//! NTT is widely used for the multiplication of two polynomials in field.
//!
//! The goal of this IOP is to prove:
//!
//! Given M instances of addition in Zq, the main idea of this IOP is to prove:
//! For y \in \{0, 1\}^N:
//!     $$a(y) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(y, x) }$$
//! where c represents the coefficients of a degree-{N-1} polynomial and a represents the evaulations at (ω^1, ω^3, ..., ω^{2N-1}),
//!
//! Here ω is the primitive 2N-th root of unity such that ω^{2N} = 1.
//! F is the standard Fourier matrix with only 2N distinct values and F(y, x) = ω^{(2Y-1)X} where Y and X are the field representations for the binary representations y and x, respectively.
//!
//! The LHS and RHS of the above equation are both MLE for y, so it can be reduced to check at a random point due to Schwartz-Zippel Lemma.
//! The remaining thing is to prove $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$ with the sumcheck protocol
//! where u is the random challenge from the verifier.
//!
//! Without delegation, the verifier needs to compute F(u, v) on his own using the same algorithm as the prover, which costs O(N).
//! In order to keep a succinct verifier, the computation of F(u, v) can be delegated to prover.
//!
//! We define $A_{F}^{(k)}:\{0,1\}^{k+1} -> \mathbb{F}$ and $ω^{(k)}_{i+1}:\{0,1\}^{k+1} -> \mathbb{F}$.
//! Note that k + i + 1= \log N.
//! In each round, the prover wants to prove, for all $x\in \{0,1\}^i$, b\in \{0,1\}:
//! A_{F}^{(k)}(x, b)=A_{F}^{(k-1)}(x) * (1-u_{i} + u_{i} * \ω^{(k)}_{i+1}(x, b)) * ω^{2^k * b}
//! where $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$.
//! So, it is reduced to prove the the following sum = \tilde{A}_{F}^{(k)}(x, b) at a random point $(x, b)\in \mathbb{F}^{k+1}$:
//!     =\sum_{z\in \{0,1\}}^k
//!         \tilde{\beta}((x, b),(z,0)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 0)
//!       + \tilde{\beta}((x, b),(z,1)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 1) * ω^{2^k}

use crate::sumcheck::prover::ProverState;
use crate::sumcheck::verifier::SubClaim;
use crate::sumcheck::MLSumcheck;
use crate::sumcheck::Proof;
use crate::utils::{eval_identity_function, gen_identity_evaluations};
use std::marker::PhantomData;
use std::rc::Rc;

use algebra::{
    DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension,
    PolynomialInfo,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;

use ntt_bare::{NTTBareIOP, NTTBareProof, NTTBareSubclaim};

pub mod ntt_bare;
/// SNARKs for NTT, i.e. $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
pub struct NTTIOP<F: Field>(PhantomData<F>);

/// proof generated by prover
pub struct NTTProof<F: Field> {
    /// bare ntt proof for proving $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    pub ntt_bare_proof: NTTBareProof<F>,
    /// sumcheck proof for $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    /// collective sumcheck proofs for delegation
    pub delegation_sumcheck_msgs: Vec<Proof<F>>,
    /// collective claimed sums for delegation
    pub delegation_claimed_sums: Vec<F>,
    /// final claim
    pub final_claim: F,
}

/// subclaim returned to verifier
pub struct NTTSubclaim<F: Field> {
    /// subclaim returned in ntt bare for proving $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    pub ntt_bare_subclaim: NTTBareSubclaim<F>,
    /// the first claim in the delegation process, i.e. F(u, v)
    pub delegation_first_claim: F,
    /// the final claim in the delegation process
    pub delegation_final_claim: F,
    /// the requested point in the final claim
    pub final_point: Vec<F>,
}

/// Stores the NTT instance with the corresponding NTT table
pub struct NTTInstance<F: Field> {
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub log_n: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Rc<Vec<F>>,
    /// coefficient representation of the polynomial
    pub coeffs: Rc<DenseMultilinearExtension<F>>,
    /// point-evaluation representation of the polynomial
    pub points: Rc<DenseMultilinearExtension<F>>,
}

/// Stores the corresponding NTT table for the verifier
pub struct NTTInstanceInfo<F: Field> {
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub log_n: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Rc<Vec<F>>,
}

/// store the intermediate mles generated in each iteration in the `init_fourier_table_overall` algorithm
pub struct IntermediateMLEs<F: Field> {
    f_mles: Vec<Rc<DenseMultilinearExtension<F>>>,
    w_mles: Vec<Rc<DenseMultilinearExtension<F>>>,
}

impl<F: Field> IntermediateMLEs<F> {
    /// Initiate the vector
    pub fn new(n_rounds: u32) -> Self {
        IntermediateMLEs {
            f_mles: Vec::with_capacity(n_rounds as usize),
            w_mles: Vec::with_capacity(n_rounds as usize),
        }
    }

    /// Add the intermediate mles generated in each round
    pub fn add_round_mles(&mut self, num_vars: usize, f_mle: &[F], w_mle: Vec<F>) {
        self.f_mles
            .push(Rc::new(DenseMultilinearExtension::from_evaluations_slice(
                num_vars, f_mle,
            )));
        self.w_mles
            .push(Rc::new(DenseMultilinearExtension::from_evaluations_vec(
                num_vars, w_mle,
            )));
    }
}

/// Generate MLE for the Fourier function F(u, x) for x \in \{0, 1\}^dim where u is the random point.
/// Dynamic programming implementaion for initializing F(u, x) in NTT (derived from zkCNN: https://eprint.iacr.org/2021/673)
/// `N` is the dimension of the vector used to represent the polynomial in NTT.
///
/// In NTT, the Fourier matrix is different since we choose these points: ω^1, ω^3, ..., ω^{2N-1}
/// Compared to the original induction, the main differences here are F(y, x)  = ω^{(2Y+1) * X} and Y = \sum_{i = 0} y_i * 2^i.
/// The latter one indicates that we use little-endian.
/// As a result, the equation (8) in zkCNN is F(u, x) = ω^X * \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X})
///
/// In order to delegate the computation F(u, v) to prover, we decompose the ω^X term into the grand product.
/// Hence, the final equation is F(u, x) = \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
///
/// * In order to comprehend this implementation, it is strongly recommended to read the pure version `naive_init_fourier_table` and `init_fourier_table` in the `ntt_bare.rs`.
/// `naive_init_fourier_table` shows the original formula of this algorithm.
/// `init_fourier_table` shows the dynamic programming version of this algorithm.
/// `init_fourier_table_overall` (this function) stores many intermediate evaluations for the ease of the delegation of F(u, v)
///
/// # Arguments
/// * u: the random point
/// * ntt_table: It stores the NTT table: ω^0, ω^1, ..., ω^{2N - 1}
pub fn init_fourier_table_overall<F: Field>(u: &[F], ntt_table: &[F]) -> IntermediateMLEs<F> {
    let log_n = u.len(); // N = 1 << dim
    let m = ntt_table.len(); // M = 2N = 2 * (1 << dim)

    // It store the evaluations of all F(u, x) for x \in \{0, 1\}^dim.
    // Note that in our implementation, we use little endian form, so the index `0b1011`
    // represents the point `P(1,1,0,1)` in {0,1}^`dim`
    let mut evaluations: Vec<_> = vec![F::ZERO; 1 << log_n];
    evaluations[0] = F::ONE;

    // stores all the intermediate evaluations of the table (i.e. F(u, x)) and the term ω^{2^{i + 1} * X} in each iteration
    let mut intermediate_mles = <IntermediateMLEs<F>>::new(log_n as u32);

    // * Compute \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
    // The reason why we update the table with u_i in reverse order is that
    // in round i, ω^{2^{i + 1} is the (M / (2^{i+1}))-th root of unity, e.g. i = dim - 1, ω^{2^{i + 1} is the 2-th root of unity.
    // Hence, we need to align this with the update method in dynamic programming.
    //
    // Note that the last term ω^{2^i * x_i} is indeed multiplied in the normal order, from x_0 to x_{log{n-1}}
    // since we actually iterate from the LSB to MSB  when updating the table from size 1, 2, 4, 8, ..., n in dynamic programming.
    for i in (0..log_n).rev() {
        // i starts from log_n - 1 and ends to 0
        let this_round_dim = log_n - i;
        let last_round_dim = this_round_dim - 1;
        let this_round_table_size = 1 << this_round_dim;
        let last_round_table_size = 1 << last_round_dim;

        let mut evaluations_w_term = vec![F::ZERO; this_round_table_size];
        for x in (0..this_round_table_size).rev() {
            // idx is to indicate the power ω^{2^{i + 1} * X} in ntt_table
            let idx = (1 << (i + 1)) * x % m;
            // the bit index in this iteration is last_round_dim = this_round_dim - 1
            // If x >= last_round_table_size, meaning the bit = 1, we need to multiply by ω^{2^last_round_dim * 1}
            if x >= last_round_table_size {
                evaluations[x] = evaluations[x % last_round_table_size]
                    * (F::ONE - u[i] + u[i] * ntt_table[idx])
                    * ntt_table[1 << last_round_dim];
            }
            // the bit index in this iteration is last_round_dim = this_round_dim - 1
            // If x < last_round_table_size, meaning the bit = 0, we do not need to multiply because ω^{2^last_round_dim * 0} = 1
            else {
                evaluations[x] = evaluations[x % last_round_table_size]
                    * (F::ONE - u[i] + u[i] * ntt_table[idx]);
            }
            evaluations_w_term[x] = ntt_table[idx];
        }
        intermediate_mles.add_round_mles(
            this_round_dim,
            &evaluations[..this_round_table_size],
            evaluations_w_term,
        );
    }

    intermediate_mles
}

/// Naive implementation for computing the MLE: w^{2^exp \cdot x} for x \in \{0, 1\}^x_dim in a naive method
///
/// # Arguments:
///
/// * ntt_table: NTT table for w (M-th root of unity) containing {1, w, w^1, ..., w^{M-1}}
/// * log_m: log of M
/// * x_dim: dimension of x or the num of variables of the outputted mle
/// * exp: the exponent of the function defined above
pub fn naive_w_power_times_x_table<F: Field>(
    ntt_table: &[F],
    log_m: usize,
    x_dim: usize,
    exp: usize,
) -> DenseMultilinearExtension<F> {
    let m = 1 << log_m; // M = 2N = 2 * (1 << dim)
    assert_eq!(ntt_table.len(), m);

    let mut evaluations: Vec<_> = (0..(1 << x_dim)).map(|_| F::ONE).collect();
    for x in 0..(1 << x_dim) {
        evaluations[x] = ntt_table[(1 << exp) * x % m];
    }
    DenseMultilinearExtension::from_evaluations_vec(x_dim, evaluations)
}

/// Evaluate the mle w^{2^exp * x} for a random point r \in F^{x_dim}
/// This formula is also derived from the techniques in zkCNN: https://eprint.iacr.org/2021/673.
/// w^{2^exp * r} = \sum_x eq(x, r) *  w^{2^exp * x}
///               = \prod_i (1 - r_i + r_i * w^{2^ {(exp + i) % log_m})
/// * Note that the above equation only holds for exp <= logM - x_dim;
/// * otherwise, the exponent 2^exp * x involves a modular addition, disabling the decomposition.
/// (Although I am not clearly making it out, the experiement result shows the above argument.)
///
/// # Arguments:
///
/// * ntt_table: NTT table for w (M-th root of unity) containing {1, w, w^1, ..., w^{M-1}}
/// * log_m: log of M
/// * x_dim: dimension of x or the num of variables of the outputted mle
/// * exp: the exponent of the function defined above
/// * r: random point in F^{x_dim}
pub fn eval_w_power_times_x<F: Field>(
    ntt_table: &[F],
    log_m: usize,
    x_dim: usize,
    exp: usize,
    r: &[F],
) -> F {
    assert_eq!(ntt_table.len(), 1 << log_m);
    assert_eq!(x_dim, r.len());
    assert!(exp + x_dim <= log_m);
    let mut prod = F::ONE;

    for (i, &r_i) in r.iter().enumerate() {
        let log_exp = (exp + i) % log_m;
        prod *= F::ONE - r_i + r_i * ntt_table[1 << log_exp];
    }

    prod
}

impl<F: Field> NTTInstance<F> {
    /// Extract the information of the NTT Instance for verification
    #[inline]
    pub fn info(&self) -> NTTInstanceInfo<F> {
        NTTInstanceInfo {
            log_n: self.log_n,
            ntt_table: Rc::clone(&self.ntt_table),
        }
    }

    /// Constuct a new instance from vector
    #[inline]
    pub fn from_vec(
        log_n: usize,
        ntt_table: &Rc<Vec<F>>,
        coeffs: &Rc<DenseMultilinearExtension<F>>,
        points: &Rc<DenseMultilinearExtension<F>>,
    ) -> Self {
        Self {
            log_n,
            ntt_table: ntt_table.clone(),
            coeffs: Rc::clone(coeffs),
            points: Rc::clone(points),
        }
    }

    /// Constuct a new instance from slice
    #[inline]
    pub fn from_slice(
        log_n: usize,
        ntt_table: &Rc<Vec<F>>,
        coeffs: &Rc<DenseMultilinearExtension<F>>,
        points: &Rc<DenseMultilinearExtension<F>>,
    ) -> Self {
        Self {
            log_n,
            ntt_table: ntt_table.clone(),
            coeffs: Rc::clone(coeffs),
            points: Rc::clone(points),
        }
    }

    /// Constuct a new instance from given info
    #[inline]
    pub fn from_info(info: &NTTInstanceInfo<F>) -> Self {
        Self {
            log_n: info.log_n,
            ntt_table: info.ntt_table.to_owned(),
            coeffs: Rc::new(<DenseMultilinearExtension<F>>::from_evaluations_vec(
                info.log_n,
                vec![F::ZERO; 1 << info.log_n],
            )),
            points: Rc::new(<DenseMultilinearExtension<F>>::from_evaluations_vec(
                info.log_n,
                vec![F::ZERO; 1 << info.log_n],
            )),
        }
    }
}

impl<F: Field> NTTSubclaim<F> {
    /// verify the subcliam
    #[inline]
    pub fn verify_subcliam(
        &self,
        points: &DenseMultilinearExtension<F>,
        coeffs: &DenseMultilinearExtension<F>,
        u: &[F],
        info: &NTTInstanceInfo<F>,
    ) -> bool {
        assert_eq!(u.len(), info.log_n);

        // check1: check the subclaim for ntt bare, i.e. $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
        // Note that the verifier delegates the computation F(u, v) to prover, so F(u, v) is included.
        if !self.ntt_bare_subclaim.verify_subclaim_with_delegation(
            self.delegation_first_claim,
            points,
            coeffs,
            u,
        ) {
            return false;
        }

        // check2: check the final claim returned from the last round of delegation
        let idx = 1 << (info.log_n);
        let eval = eval_identity_function(&self.final_point, &[F::ZERO])
            + eval_identity_function(&self.final_point, &[F::ONE])
                * (F::ONE - u[info.log_n - 1] + u[info.log_n - 1] * info.ntt_table[idx])
                * info.ntt_table[1];

        self.delegation_final_claim == eval
    }
}

impl<F: Field> NTTIOP<F> {
    /// prove
    pub fn prove(ntt_instance: &NTTInstance<F>, u: &[F]) -> NTTProof<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::prove_as_subprotocol(&mut fs_rng, ntt_instance, u)
    }

    /// The delegation of F(u, v) consists of logN - 1 rounds, each of which is a sumcheck protocol.
    ///
    /// We define $A_{F}^{(k)}:\{0,1\}^{k+1} -> \mathbb{F}$ and $ω^{(k)}_{i+1}:\{0,1\}^{k+1} -> \mathbb{F}$.
    /// The prover asserts the following sum = \tilde{A}_{F}^{(k)}(x, b) at a random point $(x, b)\in \mathbb{F}^{k+1}$:
    /// sum = \sum_{z\in \{0,1\}}^k
    ///         \tilde{\beta}((x, b),(z,0)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 0)
    ///       + \tilde{\beta}((x, b),(z,1)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 1) * ω^{2^k}
    /// where $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$.
    ///
    /// In the term of the data structure, the polynomial to be sumed can be viewed as the sum of two products,
    /// one has coefficient one, and the other has coefficient ω^{2^k}.
    ///
    /// # Arguments
    /// * round: round number denoted by k, which is iterated in a reverse order as described in the algorithm
    /// * point: the random point $(x, b)\in \mathbb{F}^{k+1}$ reduced from the last sumcheck, used to prove the sum in the round
    /// * u_i: parameter in this round as described in the formula
    /// * w_coeff: the coefficient ω^{2^k} of the second product
    /// * f: MLE \tilde{A}_{F}^{(k-1)}(z) for z\in \{0,1\}^k
    /// * w: MLE \tilde{ω}^{(k)}_{i+1}(z, b) for z\in \{0,1\}^k  and b\in \{0, 1\}, which will be divided into two smaller MLEs \tilde{ω}^{(k)}_{i+1}(z, 0) and \tilde{ω}^{(k)}_{i+1}(z, 1)
    pub fn delegation_prover_round(
        fs_rng: &mut impl RngCore,
        round: usize,
        point: &[F],
        u_i: F,
        w_coeff: F,
        f: &Rc<DenseMultilinearExtension<F>>,
        w: &Rc<DenseMultilinearExtension<F>>,
    ) -> (Proof<F>, ProverState<F>) {
        assert_eq!(f.num_vars, round);
        assert_eq!(w.num_vars, round + 1);

        let mut poly = <ListOfProductsOfPolynomials<F>>::new(round);
        let mut product_left = Vec::with_capacity(3);
        let mut product_right = Vec::with_capacity(3);
        let mut ops_left = Vec::with_capacity(3);
        let mut ops_right = Vec::with_capacity(3);

        // the equality function defined by the random point $(x, b)\in \mathbb{F}^{k+1}$
        // it is divided into two MLEs \tilde{\beta}((x, b),(z,0)) and \tilde{\beta}((x, b),(z,1))
        let eq_func = gen_identity_evaluations(point);
        let (eq_func_left, eq_func_right) = eq_func.split_halves();

        // two divided MLEs: \tilde{ω}^{(k)}_{i+1}(z, 0) and \tilde{ω}^{(k)}_{i+1}(z, 1)
        let (w_left, w_right) = w.split_halves();

        // construct the polynomial to be sumed
        // left product is \tilde{\beta}((x, b),(z,0)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 0)
        // right product is \tilde{\beta}((x, b),(z,1)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 1) * ω^{2^k}
        product_left.push(Rc::new(eq_func_left));
        ops_left.push((F::ONE, F::ZERO));
        product_left.push(Rc::clone(f));
        ops_left.push((F::ONE, F::ZERO));
        product_left.push(Rc::new(w_left));
        ops_left.push((u_i, F::ONE - u_i));
        poly.add_product_with_linear_op(product_left, &ops_left, F::ONE);

        product_right.push(Rc::new(eq_func_right));
        ops_right.push((F::ONE, F::ZERO));
        product_right.push(Rc::clone(f));
        ops_right.push((F::ONE, F::ZERO));
        product_right.push(Rc::new(w_right));
        ops_right.push((u_i, F::ONE - u_i));
        poly.add_product_with_linear_op(product_right, &ops_right, w_coeff);

        MLSumcheck::prove_as_subprotocol(fs_rng, &poly)
            .expect("ntt proof of delegation failed in round {round}")
    }

    /// prove NTT with delegation
    pub fn prove_as_subprotocol(
        fs_rng: &mut impl RngCore,
        ntt_instance: &NTTInstance<F>,
        u: &[F],
    ) -> NTTProof<F> {
        let log_n = ntt_instance.log_n;

        let intermediate_mles = init_fourier_table_overall(u, &ntt_instance.ntt_table);
        let (f_mles, w_mles) = (intermediate_mles.f_mles, intermediate_mles.w_mles);

        // 1. prove a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) } for a random point u
        let f_u = &f_mles[log_n - 1];
        let (ntt_bare_proof, state) =
            NTTBareIOP::prove_as_subprotocol(fs_rng, f_u, ntt_instance, u);

        // the above sumcheck is reduced to prove F(u, v) where v is the requested point
        let mut requested_point = state.randomness;
        let mut reduced_claim = f_mles[log_n - 1].evaluate(&requested_point);

        // 2. prove the computation of F(u, v) in log_n - 1 rounds

        // store the sumcheck proof in each round
        let mut delegation_sumcheck_msgs = Vec::with_capacity(log_n - 1);
        // store the claimed sum of the sumcheck protocol in each round
        let mut delegation_claimed_sums = Vec::with_capacity(log_n - 1);
        for k in (1..log_n).rev() {
            // start form log_n - 1;
            let i = log_n - 1 - k;
            delegation_claimed_sums.push(reduced_claim);

            let w_coeff = ntt_instance.ntt_table[1 << k];
            let f = &f_mles[k - 1];
            let (proof_round, state_round) = Self::delegation_prover_round(
                fs_rng,
                k,
                &requested_point,
                u[i],
                w_coeff,
                f,
                &w_mles[k],
            );
            delegation_sumcheck_msgs.push(proof_round);

            // the requested point returned from this round of sumcheck protocol, which initiates the claimed sum of the next round
            requested_point = state_round.randomness;
            reduced_claim = f.evaluate(&requested_point);
        }

        NTTProof {
            ntt_bare_proof,
            delegation_sumcheck_msgs,
            delegation_claimed_sums,
            final_claim: reduced_claim,
        }
    }

    /// prove NTT with delegation
    pub fn verify(
        proof: &NTTProof<F>,
        ntt_instance_info: &NTTInstanceInfo<F>,
        u: &[F],
    ) -> NTTSubclaim<F> {
        let seed: <ChaCha12Rng as SeedableRng>::Seed = Default::default();
        let mut fs_rng = ChaCha12Rng::from_seed(seed);
        Self::verify_as_subprotocol(&mut fs_rng, proof, ntt_instance_info, u)
    }

    /// The delegation of F(u, v) consists of logN - 1 rounds, each of which is a sumcheck protocol.
    ///
    /// We define $A_{F}^{(k)}:\{0,1\}^{k+1} -> \mathbb{F}$ and $ω^{(k)}_{i+1}:\{0,1\}^{k+1} -> \mathbb{F}$.
    /// The prover asserts the following sum = \tilde{A}_{F}^{(k)}(x, b) at a random point $(x, b)\in \mathbb{F}^{k+1}$:
    /// sum = \sum_{z\in \{0,1\}}^k
    ///         \tilde{\beta}((x, b),(z,0)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 0)
    ///       + \tilde{\beta}((x, b),(z,1)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 1) * ω^{2^k}
    /// where $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$.
    ///
    /// The verify needs to check the equality of the evaluation of the polynomial to be summed at a random point z = r \in \{0,1\}}^k.
    /// In verification, the verifier is given the evaluation of \tilde{A}_{F}^{(k-1)}(z = r) instead of computing on his own, so he can use it to check.
    /// If the equality holds, it is reduced to check the evaluation of \tilde{A}_{F}^{(k-1)}(z = r).
    ///
    /// # Arguments
    /// * round: round number denoted by k, which is iterated in a reverse order as described in the algorithm
    /// * x_b_point: the random point $(x, b)\in \mathbb{F}^{k+1}$ reduced from the last sumcheck
    /// * u_i: parameter in this round as described in the formula
    /// * subclaim: the subclaim returned from this round of the sumcheck, containing the random point r used for equality check
    /// * reduced_claim: the given evaluation of \tilde{A}_{F}^{(k-1)}(z = r) so verify does not need to compute on his own
    pub fn delegation_verify_round(
        round: usize,
        x_b_point: &[F],
        u_i: F,
        subclaim: &SubClaim<F>,
        reduced_claim: F,
        ntt_instance_info: &NTTInstanceInfo<F>,
    ) -> bool {
        let log_n = ntt_instance_info.log_n;
        let ntt_table = &ntt_instance_info.ntt_table;

        // r_left = (r, 0) and r_right = (r, 0)
        let mut r_left: Vec<_> = Vec::with_capacity(round + 1);
        let mut r_right: Vec<_> = Vec::with_capacity(round + 1);
        r_left.extend(&subclaim.point);
        r_right.extend(&subclaim.point);
        r_left.push(F::ZERO);
        r_right.push(F::ONE);

        // compute $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$ at point (r, 0) and (r, 1)
        // exp: i + 1 = n - k
        let exp = log_n - round;
        // w_left = \tilde{ω}^{(k)}_{i+1}(r, 0) and w_right = \tilde{ω}^{(k)}_{i+1}(r, 0)
        let w_left = eval_w_power_times_x(ntt_table, log_n + 1, round + 1, exp, &r_left);
        let w_right = eval_w_power_times_x(ntt_table, log_n + 1, round + 1, exp, &r_right);

        let eval = eval_identity_function(x_b_point, &r_left)
            * reduced_claim
            * (F::ONE - u_i + u_i * w_left)
            + eval_identity_function(x_b_point, &r_right)
                * reduced_claim
                * (F::ONE - u_i + u_i * w_right)
                * ntt_table[1 << round];

        eval == subclaim.expected_evaluations
    }

    /// verify NTT with delegation
    pub fn verify_as_subprotocol(
        fs_rng: &mut impl RngCore,
        proof: &NTTProof<F>,
        ntt_instance_info: &NTTInstanceInfo<F>,
        u: &[F],
    ) -> NTTSubclaim<F> {
        let log_n = ntt_instance_info.log_n;
        assert_eq!(proof.delegation_sumcheck_msgs.len(), log_n - 1);
        assert_eq!(proof.delegation_claimed_sums.len(), log_n - 1);

        // TODO sample randomness via Fiat-Shamir RNG
        // 1. verify a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) } for a random point u
        let ntt_bare_subclaim =
            NTTBareIOP::verify_as_subprotocol(fs_rng, &proof.ntt_bare_proof, ntt_instance_info);

        // 2. verify the computation of F(u, v) in log_n - 1 rounds
        let mut requested_point = ntt_bare_subclaim.point.clone();
        for (cnt, k) in (1..log_n).rev().enumerate() {
            let i = log_n - 1 - k;

            // verify the proof of the sumcheck protocol
            let poly_info = PolynomialInfo {
                max_multiplicands: 3,
                num_variables: k,
            };
            let subclaim = MLSumcheck::verify_as_subprotocol(
                fs_rng,
                &poly_info,
                proof.delegation_claimed_sums[cnt],
                &proof.delegation_sumcheck_msgs[cnt],
            )
            .expect("ntt verification failed in round {cnt}");

            // In the last round of the sumcheck protocol, the verify needs to check the equality of the evaluation of the polynomial to be summed at a random point z = r \in \{0,1\}}^k.
            // The verifier is given the evaluation of \tilde{A}_{F}^{(k-1)}(z = r) instead of computing on his own, so he can use it to check.
            // If the equality holds, it is reduced to check the evaluation of \tilde{A}_{F}^{(k-1)}(z = r).
            let reduced_claim = if cnt < log_n - 2 {
                proof.delegation_claimed_sums[cnt + 1]
            } else {
                proof.final_claim
            };
            // check the equality
            if !Self::delegation_verify_round(
                k,
                &requested_point,
                u[i],
                &subclaim,
                reduced_claim,
                ntt_instance_info,
            ) {
                panic!("ntt verification failed in round {cnt}");
            }
            requested_point = subclaim.point;
        }

        // TODO: handle the case that log = 1
        assert_eq!(requested_point.len(), 1);
        NTTSubclaim {
            ntt_bare_subclaim,
            delegation_first_claim: proof.delegation_claimed_sums[0],
            delegation_final_claim: proof.final_claim,
            final_point: requested_point,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::piop::ntt::{eval_w_power_times_x, naive_w_power_times_x_table};
    use algebra::{
        derive::{Field, Prime, NTT},
        DenseMultilinearExtension, Field, FieldUniformSampler, MultilinearExtension, NTTField,
    };
    use rand::thread_rng;
    use rand_distr::Distribution;

    use super::init_fourier_table_overall;

    #[derive(Field, Prime, NTT)]
    #[modulus = 132120577]
    pub struct Fp32(u32);
    // field type
    type FF = Fp32;

    #[test]
    fn test_init_fourier_table_overall() {
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

        let mut fourier_matrix: Vec<_> = (0..(1 << dim) * (1 << dim)).map(|_| FF::ZERO).collect();
        let mut ntt_table = Vec::with_capacity(m as usize);

        let mut power = FF::ONE;
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
        let partial_fourier_mle = &init_fourier_table_overall(&u, &ntt_table).f_mles[dim - 1];

        assert_eq!(fourier_mle.evaluate(&u_v), partial_fourier_mle.evaluate(&v));
    }

    #[test]
    fn test_w_power_x() {
        let dim = 10; // meaning x\in \{0, 1\}^{dim} and N = 1 << dim
        let log_m = dim + 1;
        let m = 1 << log_m; // M = 2N

        // root is the M-th root of unity
        let root = FF::try_minimal_primitive_root(m).unwrap();

        let mut ntt_table = Vec::with_capacity(m as usize);

        let mut power = FF::ONE;
        for _ in 0..m {
            ntt_table.push(power);
            power *= root;
        }

        let sampler = <FieldUniformSampler<FF>>::new();
        let mut rng = thread_rng();

        for x_dim in 0..=dim {
            let max_exp = log_m - x_dim;
            for exp in 0..=max_exp {
                let r: Vec<_> = (0..x_dim).map(|_| sampler.sample(&mut rng)).collect();
                let w_mle = naive_w_power_times_x_table(&ntt_table, log_m, x_dim, exp);
                let w_eval = eval_w_power_times_x(&ntt_table, log_m, x_dim, exp, &r);
                assert_eq!(w_eval, w_mle.evaluate(&r));
            }
        }
    }
}