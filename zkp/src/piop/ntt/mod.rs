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

use crate::sumcheck::{self, ProofWrapper, SumcheckKit};
use crate::sumcheck::{prover::ProverState, verifier::SubClaim, MLSumcheck, Proof};
use crate::utils::{eval_identity_function, gen_identity_evaluations, verify_oracle_relation};
use algebra::{
    utils::Transcript, AbstractExtensionField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo,
};
use core::fmt;
use itertools::izip;
use pcs::PolynomialCommitmentScheme;
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, rc::Rc, sync::Arc};

use bincode::Result;
use ntt_bare::NTTBareIOP;

pub mod ntt_bare;

/// Types of bit order.
#[derive(Debug, Clone, Copy)]
pub enum BitsOrder {
    /// The normal order.
    Normal,
    /// The reverse order.
    Reverse,
}

/// Stores the NTT instance with the corresponding NTT table
pub struct NTTInstance<F: Field> {
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Arc<Vec<F>>,
    /// coefficient representation of the polynomial
    pub coeffs: Rc<DenseMultilinearExtension<F>>,
    /// point-evaluation representation of the polynomial
    pub points: Rc<DenseMultilinearExtension<F>>,
}

impl<F: Field> NTTInstance<F> {
    /// Extract the information of the NTT Instance for verification
    #[inline]
    pub fn info(&self) -> BatchNTTInstanceInfo<F> {
        BatchNTTInstanceInfo {
            num_ntt: 1,
            num_vars: self.num_vars,
            ntt_table: Arc::clone(&self.ntt_table),
        }
    }

    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        log_n: usize,
        ntt_table: &Arc<Vec<F>>,
        coeffs: &Rc<DenseMultilinearExtension<F>>,
        points: &Rc<DenseMultilinearExtension<F>>,
    ) -> Self {
        Self {
            num_vars: log_n,
            ntt_table: ntt_table.clone(),
            coeffs: Rc::clone(coeffs),
            points: Rc::clone(points),
        }
    }

    /// Construct a ntt instance defined over Extension Field
    #[inline]
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> NTTInstance<EF> {
        NTTInstance::<EF> {
            num_vars: self.num_vars,
            ntt_table: Arc::new(self.ntt_table.iter().map(|x| EF::from_base(*x)).collect()),
            coeffs: Rc::new(self.coeffs.to_ef::<EF>()),
            points: Rc::new(self.points.to_ef::<EF>()),
        }
    }
}

/// Store all the NTT instances over Field to be proved, which will be randomized into a single random NTT instance over Extension Field.
pub struct BatchNTTInstance<F: Field> {
    /// number of ntt instances
    pub num_ntt: usize,
    /// number of variables, which equals to logN.
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Arc<Vec<F>>,
    /// store the coefficient representations
    pub coeffs: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// store the point-evaluation representation
    pub points: Vec<Rc<DenseMultilinearExtension<F>>>,
}

/// Stores the corresponding NTT table for the verifier
#[derive(Clone, Debug)]
pub struct BatchNTTInstanceInfo<F: Field> {
    /// number of instances randomized into this NTT instance
    pub num_ntt: usize,
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Arc<Vec<F>>,
}

/// Stores the information to be hashed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchNTTInstanceInfoClean {
    /// number of instances randomized into this NTT instance
    pub num_ntt: usize,
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
}

impl<F: Field> fmt::Display for BatchNTTInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a NTT instance randomized from {} NTT instances",
            self.num_ntt,
        )
    }
}

impl<F: Field> BatchNTTInstanceInfo<F> {
    /// Return the clean info.
    #[inline]
    pub fn to_clean(&self) -> BatchNTTInstanceInfoClean {
        BatchNTTInstanceInfoClean {
            num_ntt: self.num_ntt,
            num_vars: self.num_vars,
        }
    }
    /// Return the number of coefficient / point oracles
    #[inline]
    pub fn num_oracles(&self) -> usize {
        self.num_ntt
    }

    /// Return the log of the number of small polynomials used in IOP
    #[inline]
    pub fn log_num_oracles(&self) -> usize {
        self.num_oracles().next_power_of_two().ilog2() as usize
    }

    /// Generate the number of variables in the committed polynomial.
    #[inline]
    pub fn generate_num_var(&self) -> usize {
        self.num_vars + self.log_num_oracles() + 1
    }

    /// Convert to EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> BatchNTTInstanceInfo<EF> {
        BatchNTTInstanceInfo {
            num_ntt: self.num_ntt,
            num_vars: self.num_vars,
            ntt_table: Arc::new(self.ntt_table.iter().map(|x| EF::from_base(*x)).collect()),
        }
    }
}

/// All the proofs generated only in the recursive phase to prove F(u, v), which does not contain the ntt_bare_proof.
#[derive(Serialize, Deserialize)]
pub struct NTTRecursiveProof<F: Field> {
    /// sumcheck proof for $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    /// collective sumcheck proofs for delegation
    pub delegation_sumcheck_msgs: Vec<Proof<F>>,
    /// collective claimed sums for delegation
    pub delegation_claimed_sums: Vec<F>,
    /// final claim
    pub final_claim: F,
}

/// store the intermediate mles generated in each iteration in the `init_fourier_table_overall` algorithm
pub struct IntermediateMLEs<F: Field> {
    f_mles: Vec<Rc<DenseMultilinearExtension<F>>>,
    w_mles: Vec<Rc<DenseMultilinearExtension<F>>>,
}

impl<F: Field> IntermediateMLEs<F> {
    /// Initiate the vector
    pub fn new(n_rounds: usize) -> Self {
        IntermediateMLEs {
            f_mles: Vec::with_capacity(n_rounds),
            w_mles: Vec::with_capacity(n_rounds),
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
/// Dynamic programming implementation for initializing F(u, x) in NTT (derived from zkCNN: https://eprint.iacr.org/2021/673)
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
///
/// `naive_init_fourier_table` shows the original formula of this algorithm.
///
/// `init_fourier_table` shows the dynamic programming version of this algorithm.
///
/// `init_fourier_table_overall` (this function) stores many intermediate evaluations for the ease of the delegation of F(u, v)
///
/// # Arguments
///
/// * `u` - The random point
/// * `ntt_table` - The NTT table: ω^0, ω^1, ..., ω^{2N - 1}
/// * `bits_order` - The indicator of bits order.
pub fn init_fourier_table_overall<F: Field>(
    u: &[F],
    ntt_table: &[F],
    bits_order: BitsOrder,
) -> IntermediateMLEs<F> {
    let log_n = u.len(); // N = 1 << dim
    let m = ntt_table.len(); // M = 2N = 2 * (1 << dim)

    // It store the evaluations of all F(u, x) for x \in \{0, 1\}^dim.
    // Note that in our implementation, we use little endian form, so the index `0b1011`
    // represents the point `P(1,1,0,1)` in {0,1}^`dim`
    let mut evaluations: Vec<_> = vec![F::zero(); 1 << log_n];
    evaluations[0] = F::one();

    // stores all the intermediate evaluations of the table (i.e. F(u, x)) and the term ω^{2^{i + 1} * X} in each iteration
    let mut intermediate_mles = <IntermediateMLEs<F>>::new(log_n);

    // * Compute \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
    // The reason why we update the table with u_i in reverse order is that
    // in round i, ω^{2^{i + 1} is the (M / (2^{i+1}))-th root of unity, e.g. i = dim - 1, ω^{2^{i + 1} is the 2-th root of unity.
    // Hence, we need to align this with the update method in dynamic programming.
    //
    // Note that the last term ω^{2^i * x_i} is indeed multiplied in the normal order, from x_0 to x_{log{n-1}}
    // since we actually iterate from the LSB to MSB  when updating the table from size 1, 2, 4, 8, ..., n in dynamic programming.

    match bits_order {
        BitsOrder::Normal => {
            for i in (0..log_n).rev() {
                // i starts from log_n - 1 and ends to 0
                let this_round_dim = log_n - i;
                let last_round_dim = this_round_dim - 1;
                let this_round_table_size = 1 << this_round_dim;
                let last_round_table_size = 1 << last_round_dim;

                let mut evaluations_w_term = vec![F::zero(); this_round_table_size];
                for x in (0..this_round_table_size).rev() {
                    // idx is to indicate the power ω^{2^{i + 1} * X} in ntt_table
                    let idx = (1 << (i + 1)) * x % m;
                    // the bit index in this iteration is last_round_dim = this_round_dim - 1
                    // If x >= last_round_table_size, meaning the bit = 1, we need to multiply by ω^{2^last_round_dim * 1}
                    if x >= last_round_table_size {
                        evaluations[x] = evaluations[x % last_round_table_size]
                            * (F::one() - u[i] + u[i] * ntt_table[idx])
                            * ntt_table[1 << last_round_dim];
                    }
                    // the bit index in this iteration is last_round_dim = this_round_dim - 1
                    // If x < last_round_table_size, meaning the bit = 0, we do not need to multiply because ω^{2^last_round_dim * 0} = 1
                    else {
                        evaluations[x] = evaluations[x % last_round_table_size]
                            * (F::one() - u[i] + u[i] * ntt_table[idx]);
                    }
                    evaluations_w_term[x] = ntt_table[idx];
                }
                intermediate_mles.add_round_mles(
                    this_round_dim,
                    &evaluations[..this_round_table_size],
                    evaluations_w_term,
                );
            }
        }

        BitsOrder::Reverse => {
            for (i, u_i) in u.iter().enumerate() {
                // i starts from log_n - 1 and ends to 0
                let this_round_dim = i + 1;
                let last_round_dim = this_round_dim - 1;
                let this_round_table_size = 1 << this_round_dim;
                let last_round_table_size = 1 << last_round_dim;

                let mut evaluations_w_term = vec![F::zero(); this_round_table_size];
                for x in (0..this_round_table_size).rev() {
                    let idx = (1 << (log_n - i)) * x % m;
                    // the bit index in this iteration is last_round_dim = this_round_dim - 1
                    // If x >= last_round_table_size, meaning the bit = 1, we need to multiply by ω^{2^last_round_dim * 1}
                    if x >= last_round_table_size {
                        evaluations[x] = evaluations[x % last_round_table_size]
                            * (F::one() - *u_i + *u_i * ntt_table[idx])
                            * ntt_table[1 << last_round_dim];
                    }
                    // the bit index in this iteration is last_round_dim = this_round_dim - 1
                    // If x < last_round_table_size, meaning the bit = 0, we do not need to multiply because ω^{2^last_round_dim * 0} = 1
                    else {
                        evaluations[x] = evaluations[x % last_round_table_size]
                            * (F::one() - *u_i + *u_i * ntt_table[idx]);
                    }
                    evaluations_w_term[x] = ntt_table[idx];
                }
                intermediate_mles.add_round_mles(
                    this_round_dim,
                    &evaluations[..this_round_table_size],
                    evaluations_w_term,
                );
            }
        }
    }
    intermediate_mles
}

/// Naive implementation for computing the MLE: w^{2^exp \cdot x} for x \in \{0, 1\}^x_dim in a naive method
///
/// # Arguments:
///
/// * `ntt_table` - The NTT table for w (M-th root of unity) containing {1, w, w^1, ..., w^{M-1}}
/// * `log_m` - The log of M
/// * `x_dim` - The dimension of x or the num of variables of the outputted mle
/// * `exp` - The exponent of the function defined above
pub fn naive_w_power_times_x_table<F: Field>(
    ntt_table: &[F],
    log_m: usize,
    x_dim: usize,
    exp: usize,
) -> DenseMultilinearExtension<F> {
    let m = 1 << log_m; // M = 2N = 2 * (1 << dim)
    assert_eq!(ntt_table.len(), m);

    let mut evaluations: Vec<_> = (0..(1 << x_dim)).map(|_| F::one()).collect();
    for x in 0..(1 << x_dim) {
        evaluations[x] = ntt_table[(1 << exp) * x % m];
    }
    DenseMultilinearExtension::from_evaluations_vec(x_dim, evaluations)
}

/// This is for the reverse order.
pub fn naive_w_power_times_x_table_reverse_order<F: Field>(
    ntt_table: &[F],
    log_m: usize,
    x_dim: usize,
    sub: usize,
) -> DenseMultilinearExtension<F> {
    let m = 1 << log_m; // M = 2N = 2 * (1 << dim)
    assert_eq!(ntt_table.len(), m);
    assert_eq!(sub, x_dim);

    let mut evaluations: Vec<_> = (0..(1 << x_dim)).map(|_| F::one()).collect();
    for x in 0..(1 << x_dim) {
        evaluations[x] = ntt_table[(1 << (log_m - sub)) * x % m];
    }
    DenseMultilinearExtension::from_evaluations_vec(x_dim, evaluations)
}

/// Evaluate the mle w^{2^exp * x} for a random point r \in F^{x_dim}
/// This formula is also derived from the techniques in [zkCNN](https://eprint.iacr.org/2021/673).
///
/// w^{2^exp * r} = \sum_x eq(x, r) *  w^{2^exp * x}
///               = \prod_i (1 - r_i + r_i * w^{2^ {(exp + i) % log_m})
///
/// * Note that the above equation only holds for exp <= logM - x_dim;
/// * otherwise, the exponent 2^exp * x involves a modular addition, disabling the decomposition.
///
/// # Arguments:
///
/// * `ntt_table` - The NTT table for w (M-th root of unity) containing {1, w, w^1, ..., w^{M-1}}
/// * `log_m` - The log of M
/// * `x_dim` - The dimension of x or the num of variables of the outputted mle
/// * `exp` - The exponent of the function defined above
/// * `r` - The random point in F^{x_dim}
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
    let mut prod = F::one();

    for (i, &r_i) in r.iter().enumerate() {
        let log_exp = (exp + i) % log_m;
        prod *= F::one() - r_i + r_i * ntt_table[1 << log_exp];
    }

    prod
}

/// This is for the reverse order.
pub fn eval_w_power_times_x_reverse_order<F: Field>(
    ntt_table: &[F],
    log_m: usize,
    x_dim: usize,
    sub: usize,
    r: &[F],
) -> F {
    assert_eq!(ntt_table.len(), 1 << log_m);
    assert_eq!(x_dim, r.len());
    assert_eq!(sub, x_dim);
    let mut prod = F::one();

    for (i, &r_i) in r.iter().enumerate() {
        let log_exp = (log_m - sub + i) % log_m;
        prod *= F::one() - r_i + r_i * ntt_table[1 << log_exp];
    }

    prod
}

impl<F: Field> BatchNTTInstance<F> {
    /// Construct an empty container
    #[inline]
    pub fn new(num_vars: usize, ntt_table: &Arc<Vec<F>>) -> Self {
        Self {
            num_ntt: 0,
            num_vars,
            ntt_table: Arc::clone(ntt_table),
            coeffs: Vec::new(),
            points: Vec::new(),
        }
    }

    /// Extract the information of the NTT Instance for verification
    #[inline]
    pub fn info(&self) -> BatchNTTInstanceInfo<F> {
        BatchNTTInstanceInfo {
            num_ntt: self.num_ntt,
            num_vars: self.num_vars,
            ntt_table: Arc::clone(&self.ntt_table),
        }
    }

    /// Add an ntt instance into the container
    #[inline]
    pub fn add_ntt_instance(
        &mut self,
        coeff: &Rc<DenseMultilinearExtension<F>>,
        point: &Rc<DenseMultilinearExtension<F>>,
    ) {
        self.num_ntt += 1;
        assert_eq!(self.num_vars, coeff.num_vars);
        assert_eq!(self.num_vars, point.num_vars);
        self.coeffs.push(Rc::clone(coeff));
        self.points.push(Rc::clone(point));
    }

    /// Pack all the involved small polynomials into a single vector of evaluations.
    /// The arrangement of this packed MLE is not as compact as others.
    /// We deliberately do like this for ease of requested evaluation on the committed polynomial.
    #[inline]
    pub fn pack_all_mles(&self) -> Vec<F> {
        let info = self.info();
        let num_vars_added_half = info.log_num_oracles();
        let num_zeros_padded_half =
            ((1 << num_vars_added_half) - info.num_oracles()) * (1 << self.num_vars);

        // arrangement: all coeffs || padded zeros || all points || padded zeros
        // The advantage of this arrangement is that F(0, x) packs all evaluations of coeff-MLEs and F(1, x) packs all evaluations of point-MLEs
        let padded_zeros = vec![F::zero(); num_zeros_padded_half];
        self.coeffs
            .iter()
            .flat_map(|coeff| coeff.iter())
            .chain(padded_zeros.iter())
            .chain(self.points.iter().flat_map(|point| point.iter()))
            .chain(padded_zeros.iter())
            .copied()
            .collect::<Vec<F>>()
    }

    /// Generate the oracle to be committed that is composed of all the small oracles used in IOP.
    /// The evaluations of this oracle is generated by the evaluations of all mles and the padded zeros.
    /// The arrangement of this oracle should be consistent to its usage in verifying the subclaim.
    #[inline]
    pub fn generate_oracle(&self) -> DenseMultilinearExtension<F> {
        let num_vars = self.info().generate_num_var();
        // arrangement: all coeffs || padded zeros || all points || padded zeros
        // The advantage of this arrangement is that F(0, x) packs all evaluations of coeff-MLEs and F(1, x) packs all evaluations of point-MLEs
        let evals = self.pack_all_mles();
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a random ntt instances from all the ntt instances to be proved, with randomness defined over Field
    ///
    /// # Arguments.
    ///
    /// * `randomnss` - The randomness used for random linear combination.
    #[inline]
    pub fn extract_ntt_instance(&self, randomness: &[F]) -> NTTInstance<F> {
        assert_eq!(randomness.len(), self.num_ntt);
        let mut random_coeffs = <DenseMultilinearExtension<F>>::from_evaluations_vec(
            self.num_vars,
            vec![F::zero(); 1 << self.num_vars],
        );
        let mut random_points = <DenseMultilinearExtension<F>>::from_evaluations_vec(
            self.num_vars,
            vec![F::zero(); 1 << self.num_vars],
        );
        for (r, coeff, point) in izip!(randomness, &self.coeffs, &self.points) {
            random_coeffs += (*r, coeff.as_ref());
            random_points += (*r, point.as_ref());
        }
        NTTInstance::<F> {
            num_vars: self.num_vars,
            ntt_table: Arc::clone(&self.ntt_table),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }

    /// Construct a random ntt instances from all the ntt instances to be proved, with randomness defined over Extension Field
    /// # Arguments.
    ///
    /// * `randomnss` - The randomness used for random linear combination.
    #[inline]
    pub fn extract_ntt_instance_to_ef<EF: AbstractExtensionField<F>>(
        &self,
        randomness: &[EF],
    ) -> NTTInstance<EF> {
        assert_eq!(randomness.len(), self.num_ntt);
        let mut random_coeffs = <DenseMultilinearExtension<EF>>::from_evaluations_vec(
            self.num_vars,
            vec![EF::zero(); 1 << self.num_vars],
        );
        let mut random_points = <DenseMultilinearExtension<EF>>::from_evaluations_vec(
            self.num_vars,
            vec![EF::zero(); 1 << self.num_vars],
        );
        for (r, coeff, point) in izip!(randomness, &self.coeffs, &self.points) {
            // multiplication between EF (r) and F (y)
            random_coeffs
                .iter_mut()
                .zip(coeff.iter())
                .for_each(|(x, y)| *x += *r * *y);
            random_points
                .iter_mut()
                .zip(point.iter())
                .for_each(|(x, y)| *x += *r * *y);
        }
        NTTInstance::<EF> {
            num_vars: self.num_vars,
            ntt_table: Arc::new(self.ntt_table.iter().map(|x| EF::from_base(*x)).collect()),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }
}

/// IOP for NTT
#[derive(Default)]
pub struct NTTIOP<F: Field> {
    /// The randomness to combine all the NTT instances.
    pub rlc_randomness: Vec<F>,
    /// The random value for initiating sumcheck.
    pub u: Vec<F>,
}

impl<F: Field + Serialize> NTTIOP<F> {
    /// Sample the random coins before proving sumcheck protocol
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The batched ntt instance info without ntt table.
    pub fn sample_coins(trans: &mut Transcript<F>, info: &BatchNTTInstanceInfoClean) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            Self::num_coins(info),
        )
    }

    /// Return the number of coins used in this IOP
    ///
    /// # Arguments.
    ///
    /// * `info` - The batched ntt instance info without ntt table.
    pub fn num_coins(info: &BatchNTTInstanceInfoClean) -> usize {
        info.num_ntt
    }

    /// Generate the randomness.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The batched ntt instance info without ntt table.
    #[inline]
    pub fn generate_randomness(
        &mut self,
        trans: &mut Transcript<F>,
        info: &BatchNTTInstanceInfoClean,
    ) {
        self.rlc_randomness = Self::sample_coins(trans, info);
    }

    /// Generate the randomness for the eq function.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `info` - The batched ntt instance info without ntt table.
    #[inline]
    pub fn generate_randomness_for_eq_function(
        &mut self,
        trans: &mut Transcript<F>,
        info: &BatchNTTInstanceInfoClean,
    ) {
        self.u = trans.get_vec_challenge(
            b"NTT IOP: random point used to instantiate sumcheck protocol",
            info.num_vars,
        );
    }

    /// Set the randomness for the eq function.
    ///
    /// # Arguments.
    ///
    /// * `u` - The vector to be set.
    #[inline]
    pub fn set_randomness_for_eq_function(&mut self, u: &[F]) {
        self.u = u.to_vec();
    }

    /// Prove NTT instance with delegation
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `instance` - The (randomized) ntt instance.
    /// * `bits_order` - The indicator of bits order.
    pub fn prove(
        &self,
        trans: &mut Transcript<F>,
        instance: &NTTInstance<F>,
        bits_order: BitsOrder,
    ) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);

        // Just prove one NTT instance.
        let randomness = F::one();
        let mut claimed_sum = F::zero();
        NTTBareIOP::<F>::prepare_products_of_polynomial(
            randomness,
            &mut poly,
            &mut claimed_sum,
            instance,
            &self.u,
            bits_order,
        );

        let (proof, state) =
            MLSumcheck::prove(trans, &poly).expect("fail to prove the sumcheck protocol");

        // Prove F(u, v) in a recursive manner
        let recursive_proof = Self::prove_recursion(
            trans,
            &state.randomness,
            &instance.info(),
            &self.u,
            bits_order,
        );

        (
            SumcheckKit {
                proof,
                claimed_sum,
                info: poly.info(),
                u: self.u.clone(),
                randomness: state.randomness,
            },
            recursive_proof,
        )
    }

    /// Verify NTT instance with delegation
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `wrapper` - The proof wrapper.
    /// * `coeff_evals_at_r` - The (randomized) coefficient polynomial evaluated at r.
    /// * `point_evals_at_u` - The (randomized) point polynomial evaluated at u.
    /// * `info` - The batched ntt instances info.
    /// * `recursive_proof` - The recursive sumcheck proof.
    /// * `bits_order` - The indicator of bits order.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        trans: &mut Transcript<F>,
        wrapper: &mut ProofWrapper<F>,
        coeff_evals_at_r: F,
        point_evals_at_u: F,
        info: &BatchNTTInstanceInfo<F>,
        recursive_proof: &NTTRecursiveProof<F>,
        bits_order: BitsOrder,
    ) -> (bool, Vec<F>) {
        // Just verify one NTT instance.
        let randomness = F::one();

        let mut subclaim =
            MLSumcheck::verify(trans, &wrapper.info, wrapper.claimed_sum, &wrapper.proof)
                .expect("fail to verify the sumcheck protocol");

        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        if !NTTBareIOP::<F>::verify_subclaim(
            randomness,
            &mut subclaim,
            &mut wrapper.claimed_sum,
            coeff_evals_at_r,
            point_evals_at_u,
            f_delegation,
        ) {
            return (false, vec![]);
        }

        if !(subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()) {
            return (false, vec![]);
        }

        let b = Self::verify_recursion(
            trans,
            recursive_proof,
            info,
            &self.u,
            &subclaim.point,
            bits_order,
        );

        (b, subclaim.point)
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
    ///
    /// * `round` - The round number.
    /// * `point` - The random point (x, b) reduced from the last sumcheck.
    /// * `u_i` - The parameter in this round.
    /// * `w_coeff` - The coefficient ω^{2^k} of the second product.
    /// * `f` - The MLE \tilde{A}_{F}^{(k-1)}(z) for z\in \{0,1\}^k
    /// * `w` - The MLE \tilde{ω}^{(k)}_{i+1}(z, b) for z\in \{0,1\}^k  and b\in \{0, 1\}.
    pub fn prove_recursion_round(
        trans: &mut Transcript<F>,
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

        // the equality function defined by the random point $(x, b)\in \mathbb{F}^{k+1}$
        // it is divided into two MLEs \tilde{\beta}((x, b),(z,0)) and \tilde{\beta}((x, b),(z,1))
        let eq_func = gen_identity_evaluations(point);
        let (eq_func_left, eq_func_right) = eq_func.split_halves();

        // two divided MLEs: \tilde{ω}^{(k)}_{i+1}(z, 0) and \tilde{ω}^{(k)}_{i+1}(z, 1)
        let (w_left, w_right) = w.split_halves();

        // construct the polynomial to be sumed
        // left product is \tilde{\beta}((x, b),(z,0)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 0)
        // right product is \tilde{\beta}((x, b),(z,1)) * \tilde{A}_{F}^{(k-1)}(z) ( (1-u_{i})+u_{i} * \tilde{ω}^{(k)}_{i+1}(z, 1) * ω^{2^k}
        poly.add_product_with_linear_op(
            [Rc::new(eq_func_left), Rc::clone(f), Rc::new(w_left)],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (u_i, F::one() - u_i),
            ],
            F::one(),
        );

        poly.add_product_with_linear_op(
            [Rc::new(eq_func_right), Rc::clone(f), Rc::new(w_right)],
            &[
                (F::one(), F::zero()),
                (F::one(), F::zero()),
                (u_i, F::one() - u_i),
            ],
            w_coeff,
        );

        MLSumcheck::prove(trans, &poly).expect("ntt proof of delegation failed in round {round}")
    }

    /// Compared to the `prove` functionality, we just remove the phase to prove NTT bare.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `ntt_bare_randomness` - The randomness output by the NTT bare sumcheck protocol.
    /// * `info` - The batched ntt instances info.
    /// * `u` - The randomness to initiate the sumcheck protocol.
    /// * `bits_order` - The indicator of bits order.
    pub fn prove_recursion(
        trans: &mut Transcript<F>,
        ntt_bare_randomness: &[F],
        info: &BatchNTTInstanceInfo<F>,
        u: &[F],
        bits_order: BitsOrder,
    ) -> NTTRecursiveProof<F> {
        let log_n = info.num_vars;

        let intermediate_mles = init_fourier_table_overall(u, &info.ntt_table, bits_order);
        let (f_mles, w_mles) = (intermediate_mles.f_mles, intermediate_mles.w_mles);

        // 1. (detached) prove a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) } for a random point u

        // the above sumcheck is reduced to prove F(u, v) where v is the requested point
        // Note that the delegated value F(u, v) is stored in proof.delegation_claimed_sums[0].
        let mut requested_point = ntt_bare_randomness.to_owned();
        let mut reduced_claim = f_mles[log_n - 1].evaluate(&requested_point);

        // 2. prove the computation of F(u, v) in log_n - 1 rounds

        // store the sumcheck proof in each round
        let mut delegation_sumcheck_msgs = Vec::with_capacity(log_n - 1);
        // store the claimed sum of the sumcheck protocol in each round
        let mut delegation_claimed_sums = Vec::with_capacity(log_n - 1);
        for k in (1..log_n).rev() {
            match bits_order {
                BitsOrder::Normal => {
                    // start form log_n - 1;
                    let i = log_n - 1 - k;
                    delegation_claimed_sums.push(reduced_claim);

                    let w_coeff = info.ntt_table[1 << k];
                    let f = &f_mles[k - 1];
                    let (proof_round, state_round) = Self::prove_recursion_round(
                        trans,
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

                BitsOrder::Reverse => {
                    delegation_claimed_sums.push(reduced_claim);

                    let w_coeff = info.ntt_table[1 << k];
                    let f = &f_mles[k - 1];
                    let (proof_round, state_round) = Self::prove_recursion_round(
                        trans,
                        k,
                        &requested_point,
                        u[k],
                        w_coeff,
                        f,
                        &w_mles[k],
                    );

                    delegation_sumcheck_msgs.push(proof_round);

                    // the requested point returned from this round of sumcheck protocol, which initiates the claimed sum of the next round
                    requested_point = state_round.randomness;
                    reduced_claim = f.evaluate(&requested_point);
                }
            }
        }

        NTTRecursiveProof {
            delegation_sumcheck_msgs,
            delegation_claimed_sums,
            final_claim: reduced_claim,
        }
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
    ///
    /// * `round` - The round number.
    /// * `x_b_point` - The random point (x, b) reduced from the last sumcheck.
    /// * `u_i` - The parameter in this round.
    /// * `subclaim` - The subclaim returned from this round of the sumcheck.
    /// * `reduced_claim` - The given evaluation.
    /// * `bits_order` - The indicator of bits order.
    pub fn verify_recursion_round(
        round: usize,
        x_b_point: &[F],
        u_i: F,
        subclaim: &SubClaim<F>,
        reduced_claim: F,
        ntt_instance_info: &BatchNTTInstanceInfo<F>,
        bits_order: BitsOrder,
    ) -> bool {
        let log_n = ntt_instance_info.num_vars;
        let ntt_table = &ntt_instance_info.ntt_table;

        // r_left = (r, 0) and r_right = (r, 1)
        let mut r_left: Vec<_> = Vec::with_capacity(round + 1);
        let mut r_right: Vec<_> = Vec::with_capacity(round + 1);
        r_left.extend(&subclaim.point);
        r_right.extend(&subclaim.point);
        r_left.push(F::zero());
        r_right.push(F::one());

        match bits_order {
            BitsOrder::Normal => {
                // compute $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$ at point (r, 0) and (r, 1)
                // exp: i + 1 = n - k
                let exp = log_n - round;
                // w_left = \tilde{ω}^{(k)}_{i+1}(r, 0) and w_right = \tilde{ω}^{(k)}_{i+1}(r, 0)
                let w_left = eval_w_power_times_x(ntt_table, log_n + 1, round + 1, exp, &r_left);
                let w_right = eval_w_power_times_x(ntt_table, log_n + 1, round + 1, exp, &r_right);

                let eval = eval_identity_function(x_b_point, &r_left)
                    * reduced_claim
                    * (F::one() - u_i + u_i * w_left)
                    + eval_identity_function(x_b_point, &r_right)
                        * reduced_claim
                        * (F::one() - u_i + u_i * w_right)
                        * ntt_table[1 << round];

                eval == subclaim.expected_evaluations
            }
            BitsOrder::Reverse => {
                // compute $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$ at point (r, 0) and (r, 1)
                let sub = round + 1;
                // w_left = \tilde{ω}^{(k)}_{i+1}(r, 0) and w_right = \tilde{ω}^{(k)}_{i+1}(r, 0)
                let w_left = eval_w_power_times_x_reverse_order(
                    ntt_table,
                    log_n + 1,
                    round + 1,
                    sub,
                    &r_left,
                );
                let w_right = eval_w_power_times_x_reverse_order(
                    ntt_table,
                    log_n + 1,
                    round + 1,
                    sub,
                    &r_right,
                );

                let eval = eval_identity_function(x_b_point, &r_left)
                    * reduced_claim
                    * (F::one() - u_i + u_i * w_left)
                    + eval_identity_function(x_b_point, &r_right)
                        * reduced_claim
                        * (F::one() - u_i + u_i * w_right)
                        * ntt_table[1 << round];

                eval == subclaim.expected_evaluations
            }
        }
    }

    /// Compared to the `prove` functionality, we remove the phase to prove NTT bare.
    /// Also, after detaching the verification of NTT bare, verifier can directly check the recursive proofs.
    ///
    /// # Arguments.
    ///
    /// * `trans` - The transcripts.
    /// * `proof` - The recursive sumcheck proofs.
    /// * `info` - The batched ntt instances info.
    /// * `u` - The randomness to initiate sumcheck protocol.
    /// * `randomness` - The randomness output by the sumcheck protocol.
    /// * `bits_order` - The indicator of bits order.
    pub fn verify_recursion(
        trans: &mut Transcript<F>,
        proof: &NTTRecursiveProof<F>,
        info: &BatchNTTInstanceInfo<F>,
        u: &[F],
        randomness: &[F],
        bits_order: BitsOrder,
    ) -> bool {
        let log_n = info.num_vars;
        assert_eq!(proof.delegation_sumcheck_msgs.len(), log_n - 1);
        assert_eq!(proof.delegation_claimed_sums.len(), log_n - 1);

        // 1. [detached] verify a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) } for a random point u
        // Note that the delegated value F(u, v) is stored in proof.delegation_claimed_sums[0].

        // 2. verify the computation of F(u, v) in log_n - 1 rounds
        let mut requested_point = randomness.to_vec();
        for (cnt, k) in (1..log_n).rev().enumerate() {
            let i = match bits_order {
                BitsOrder::Normal => log_n - 1 - k,
                _ => 0,
            };

            // verify the proof of the sumcheck protocol
            let poly_info = PolynomialInfo {
                max_multiplicands: 3,
                num_variables: k,
            };
            let subclaim = MLSumcheck::verify(
                trans,
                &poly_info,
                proof.delegation_claimed_sums[cnt],
                &proof.delegation_sumcheck_msgs[cnt],
            )
            .expect("ntt verification failed in round {cnt}");

            // In the last round of the sumcheck protocol, the verifier needs to check the equality of the evaluation of the polynomial to be summed at a random point z = r \in \{0,1\}}^k.
            // The verifier is given the evaluation of \tilde{A}_{F}^{(k-1)}(z = r) instead of computing on his own, so he can use it to check.
            // If the equality holds, it is reduced to check the evaluation of \tilde{A}_{F}^{(k-1)}(z = r).
            let reduced_claim = if cnt < log_n - 2 {
                proof.delegation_claimed_sums[cnt + 1]
            } else {
                proof.final_claim
            };
            // check the equality
            match bits_order {
                BitsOrder::Normal => {
                    if !Self::verify_recursion_round(
                        k,
                        &requested_point,
                        u[i],
                        &subclaim,
                        reduced_claim,
                        info,
                        BitsOrder::Normal,
                    ) {
                        panic!("ntt verification failed in round {cnt}");
                    }
                    requested_point = subclaim.point;
                }
                BitsOrder::Reverse => {
                    if !Self::verify_recursion_round(
                        k,
                        &requested_point,
                        u[k],
                        &subclaim,
                        reduced_claim,
                        info,
                        BitsOrder::Reverse,
                    ) {
                        panic!("ntt verification failed in round {cnt}");
                    }
                    requested_point = subclaim.point;
                }
            }
        }

        let delegation_final_claim = proof.final_claim;
        let final_point = requested_point;
        // TODO: handle the case that log = 1
        assert_eq!(final_point.len(), 1);

        // check the final claim returned from the last round of delegation
        let idx = 1 << (info.num_vars);
        let eval = match bits_order {
            BitsOrder::Normal => {
                eval_identity_function(&final_point, &[F::zero()])
                    + eval_identity_function(&final_point, &[F::one()])
                        * (F::one() - u[info.num_vars - 1]
                            + u[info.num_vars - 1] * info.ntt_table[idx])
                        * info.ntt_table[1]
            }
            BitsOrder::Reverse => {
                eval_identity_function(&final_point, &[F::zero()])
                    + eval_identity_function(&final_point, &[F::one()])
                        * (F::one() - u[0] + u[0] * info.ntt_table[idx])
                        * info.ntt_table[1]
            }
        };

        delegation_final_claim == eval
    }
}

/// NTT proof with PCS.
#[derive(Serialize, Deserialize)]
pub struct NTTProof<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// Polynomial info.
    pub poly_info: PolynomialInfo,
    /// Polynomial commitment.
    pub poly_comm: Pcs::Commitment,
    /// The evaluation of the polynomial of coefficient on a random point.
    pub coeff_oracle_eval: EF,
    /// The opening proof of the above evaluation of the coefficient polynomial.
    pub coeff_eval_proof: Pcs::Proof,
    /// The coefficient evaluations of each NTT instance on the random point.
    pub coeff_eval: Vec<EF>,
    /// The evaluation of the polynomial of point.
    pub point_oracle_eval: EF,
    /// The opening proof of the above evaluation of the point polynomial.
    pub point_eval_proof: Pcs::Proof,
    /// The point evaluations of each NTT instance on the random point.
    pub point_eval: Vec<EF>,
    /// The sumcheck proof.
    pub sumcheck_proof: sumcheck::Proof<EF>,
    /// The recursive proof.
    pub recursive_proof: NTTRecursiveProof<EF>,
}

impl<F, EF, S, Pcs> NTTProof<F, EF, S, Pcs>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Convert into bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self)
    }

    /// Recover from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
    }
}

/// BitDecomposition parameter.
pub struct NTTParams<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    /// The parameter for the polynomial commitment.
    pub pp: Pcs::Parameters,
}

impl<F, EF, S, Pcs> Default for NTTParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        Self {
            pp: Pcs::Parameters::default(),
        }
    }
}

impl<F, EF, S, Pcs> NTTParams<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    S: Clone,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    /// Setup for the PCS.
    #[inline]
    pub fn setup(&mut self, info: &BatchNTTInstanceInfo<F>, code_spec: S) {
        self.pp = Pcs::setup(info.generate_num_var(), Some(code_spec))
    }
}

/// Prover for NTT IOT with PCS.
pub struct NTTProver<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    _marker_f: PhantomData<F>,
    _marker_ef: PhantomData<EF>,
    _marker_s: PhantomData<S>,
    _marker_pcs: PhantomData<Pcs>,
}

impl<F, EF, S, Pcs> Default for NTTProver<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        NTTProver {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> NTTProver<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The prover.
    pub fn prove(
        &self,
        trans: &mut Transcript<EF>,
        params: &NTTParams<F, EF, S, Pcs>,
        instance: &BatchNTTInstance<F>,
        bits_order: BitsOrder,
    ) -> NTTProof<F, EF, S, Pcs> {
        let instance_info = instance.info();

        trans.append_message(b"ntt instance", &instance_info.to_clean());
        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();

        // Use PCS to commit the above polynomial.
        let (poly_comm, comm_state) = Pcs::commit(&params.pp, &committed_poly);

        trans.append_message(b"NTT IOP: polynomial commitment", &poly_comm);

        // Generate the randomness for the sumcheck protocol.
        let mut iop = NTTIOP::default();
        iop.generate_randomness(trans, &instance_info.to_clean());
        iop.generate_randomness_for_eq_function(trans, &instance_info.to_clean());

        // Extract the target ntt instance, note that it is define over EF.
        let target_ntt_instance = instance.extract_ntt_instance_to_ef::<EF>(&iop.rlc_randomness);

        // Prove sumcheck protocol
        let (kit, recursive_proof) = iop.prove(trans, &target_ntt_instance, bits_order);

        // Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol.
        let eq_at_r = gen_identity_evaluations(&kit.randomness);
        let eq_at_u = gen_identity_evaluations(&iop.u);

        let coeff_evals_at_r = instance
            .coeffs
            .iter()
            .map(|x| x.evaluate_ext_opt(&eq_at_r))
            .collect::<Vec<_>>();
        let point_evals_at_u = instance
            .points
            .iter()
            .map(|x| x.evaluate_ext_opt(&eq_at_u))
            .collect::<Vec<_>>();

        // Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut coeff_requested_point = kit.randomness.clone();
        let mut point_requested_point = iop.u.clone();
        let oracle_randomness = trans.get_vec_challenge(
            b"NTT: random linear combination for evaluations of oracles",
            instance_info.log_num_oracles(),
        );
        coeff_requested_point.extend(&oracle_randomness);
        point_requested_point.extend(&oracle_randomness);
        coeff_requested_point.push(EF::zero());
        point_requested_point.push(EF::one());

        let coeff_oracle_eval = committed_poly.evaluate_ext(&coeff_requested_point);
        let point_oracle_eval = committed_poly.evaluate_ext(&point_requested_point);

        let coeff_eval_proof = Pcs::open(
            &params.pp,
            &poly_comm,
            &comm_state,
            &coeff_requested_point,
            trans,
        );

        let point_eval_proof = Pcs::open(
            &params.pp,
            &poly_comm,
            &comm_state,
            &point_requested_point,
            trans,
        );

        NTTProof {
            poly_info: kit.info,
            poly_comm,
            coeff_oracle_eval,
            coeff_eval_proof,
            coeff_eval: coeff_evals_at_r,
            point_oracle_eval,
            point_eval_proof,
            point_eval: point_evals_at_u,
            sumcheck_proof: kit.proof,
            recursive_proof,
        }
    }
}

/// Verifier for NTT IOP with PCS.
pub struct NTTVerifier<
    F: Field,
    EF: AbstractExtensionField<F>,
    S,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
> {
    _marker_f: PhantomData<F>,
    _marker_ef: PhantomData<EF>,
    _marker_s: PhantomData<S>,
    _marker_pcs: PhantomData<Pcs>,
}

impl<F, EF, S, Pcs> Default for NTTVerifier<F, EF, S, Pcs>
where
    F: Field,
    EF: AbstractExtensionField<F>,
    Pcs: PolynomialCommitmentScheme<F, EF, S>,
{
    fn default() -> Self {
        NTTVerifier {
            _marker_f: PhantomData::<F>,
            _marker_ef: PhantomData::<EF>,
            _marker_s: PhantomData::<S>,
            _marker_pcs: PhantomData::<Pcs>,
        }
    }
}

impl<F, EF, S, Pcs> NTTVerifier<F, EF, S, Pcs>
where
    F: Field + Serialize,
    EF: AbstractExtensionField<F> + Serialize,
    S: Clone,
    Pcs:
        PolynomialCommitmentScheme<F, EF, S, Polynomial = DenseMultilinearExtension<F>, Point = EF>,
{
    /// The verifier.
    pub fn verify(
        &self,
        trans: &mut Transcript<EF>,
        params: &NTTParams<F, EF, S, Pcs>,
        info: &BatchNTTInstanceInfo<F>,
        proof: &NTTProof<F, EF, S, Pcs>,
        bits_order: BitsOrder,
    ) -> bool {
        let mut res = true;

        trans.append_message(b"ntt instance", &info.to_clean());
        trans.append_message(b"NTT IOP: polynomial commitment", &proof.poly_comm);

        let mut iop = NTTIOP::default();

        iop.generate_randomness(trans, &info.to_clean());
        iop.generate_randomness_for_eq_function(trans, &info.to_clean());

        // Get evals_at_r and evals_at_u.
        let evals_at_r = iop
            .rlc_randomness
            .iter()
            .zip(proof.coeff_eval.iter())
            .fold(EF::zero(), |acc, (r, eval)| acc + *r * eval);

        let evals_at_u = iop
            .rlc_randomness
            .iter()
            .zip(proof.point_eval.iter())
            .fold(EF::zero(), |acc, (r, eval)| acc + *r * eval);

        // Check the subclaim returned from the sumcheck protocol.
        let mut wrapper = ProofWrapper {
            claimed_sum: evals_at_u,
            info: proof.poly_info,
            proof: proof.sumcheck_proof.clone(),
        };

        let (b, randomness) = iop.verify(
            trans,
            &mut wrapper,
            evals_at_r,
            evals_at_u,
            &info.to_ef(),
            &proof.recursive_proof,
            bits_order,
        );

        res &= b;

        // Check the relation between these small oracles and the committed oracle.
        let oracle_randomness = trans.get_vec_challenge(
            b"NTT: random linear combination for evaluations of oracles",
            info.log_num_oracles(),
        );
        res &= verify_oracle_relation(
            &proof.coeff_eval,
            proof.coeff_oracle_eval,
            &oracle_randomness,
        );

        res &= verify_oracle_relation(
            &proof.point_eval,
            proof.point_oracle_eval,
            &oracle_randomness,
        );

        let mut coeff_requested_points = randomness;
        coeff_requested_points.extend(&oracle_randomness);
        coeff_requested_points.push(EF::zero());
        let mut point_requested_points = iop.u.clone();
        point_requested_points.extend(&oracle_randomness);
        point_requested_points.push(EF::one());

        res &= Pcs::verify(
            &params.pp,
            &proof.poly_comm,
            &coeff_requested_points,
            proof.coeff_oracle_eval,
            &proof.coeff_eval_proof,
            trans,
        );

        res &= Pcs::verify(
            &params.pp,
            &proof.poly_comm,
            &point_requested_points,
            proof.point_oracle_eval,
            &proof.point_eval_proof,
            trans,
        );

        res
    }
}

#[cfg(test)]
mod test {
    use crate::piop::ntt::{eval_w_power_times_x, naive_w_power_times_x_table, BitsOrder};
    use algebra::{
        derive::{DecomposableField, FheField, Field, Prime, NTT},
        DenseMultilinearExtension, FieldUniformSampler, NTTField,
    };
    use num_traits::{One, Zero};
    use rand::thread_rng;
    use rand_distr::Distribution;

    use super::init_fourier_table_overall;

    #[derive(Field, DecomposableField, FheField, Prime, NTT)]
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
        let partial_fourier_mle =
            &init_fourier_table_overall(&u, &ntt_table, BitsOrder::Normal).f_mles[dim - 1];

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

        let mut power = FF::one();
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
