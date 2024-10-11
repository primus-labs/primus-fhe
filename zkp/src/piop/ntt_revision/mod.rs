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

use crate::sumcheck::{prover::ProverState, verifier::SubClaim, MLSumcheck, Proof};
use crate::sumcheck::{ProofWrapper, SumcheckKit};
use crate::utils::{
    eval_identity_function, gen_identity_evaluations, print_statistic, verify_oracle_relation,
};
use algebra::{
    utils::Transcript, AbstractExtensionField, DenseMultilinearExtension, Field,
    ListOfProductsOfPolynomials, PolynomialInfo,
};
use core::fmt;
use itertools::izip;
use pcs::{
    multilinear::brakedown::BrakedownPCS,
    utils::code::{LinearCode, LinearCodeSpec},
    utils::hash::Hash,
    PolynomialCommitmentScheme,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::rc::Rc;
use std::time::Instant;

use ntt_bare::NTTBareIOP;

pub mod ntt_bare;
/// IOP for NTT, i.e. $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
pub struct NTTIOP<F: Field>(PhantomData<F>);
/// SNARKs for NTT compiled with PCS
pub struct NTTSnarks<F: Field, EF: AbstractExtensionField<F>>(PhantomData<F>, PhantomData<EF>);

/// Stores the NTT instance with the corresponding NTT table
pub struct NTTInstance<F: Field> {
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Rc<Vec<F>>,
    /// coefficient representation of the polynomial
    pub coeffs: Rc<DenseMultilinearExtension<F>>,
    /// point-evaluation representation of the polynomial
    pub points: Rc<DenseMultilinearExtension<F>>,
}

/// All the proofs generated only in the recursive phase to prove F(u, v), which does not contain the ntt_bare_proof.
#[derive(Serialize)]
pub struct NTTRecursiveProof<F: Field> {
    /// sumcheck proof for $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    /// collective sumcheck proofs for delegation
    pub delegation_sumcheck_msgs: Vec<Proof<F>>,
    /// collective claimed sums for delegation
    pub delegation_claimed_sums: Vec<F>,
    /// final claim
    pub final_claim: F,
}

/// Store all the NTT instances over Field to be proved, which will be randomized into a single random NTT instance over Extension Field.
pub struct NTTInstances<F: Field> {
    /// number of ntt instances
    pub num_ntt: usize,
    /// number of variables, which equals to logN.
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Rc<Vec<F>>,
    /// store the coefficient representations
    pub coeffs: Vec<Rc<DenseMultilinearExtension<F>>>,
    /// store the point-evaluation representation
    pub points: Vec<Rc<DenseMultilinearExtension<F>>>,
}

/// Stores the corresponding NTT table for the verifier
#[derive(Clone)]
pub struct NTTInstanceInfo<F: Field> {
    /// number of instances randomized into this NTT instance
    pub num_ntt: usize,
    /// log_n is the number of the variables
    /// the degree of the polynomial is N - 1
    pub num_vars: usize,
    /// stores {ω^0, ω^1, ..., ω^{2N-1}}
    pub ntt_table: Rc<Vec<F>>,
}

impl<F: Field> fmt::Display for NTTInstanceInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a NTT instance randomized from {} NTT instances",
            self.num_ntt,
        )
    }
}

impl<F: Field> NTTInstanceInfo<F> {
    /// Convert to EF version
    pub fn to_ef<EF: AbstractExtensionField<F>>(&self) -> NTTInstanceInfo<EF> {
        NTTInstanceInfo {
            num_ntt: self.num_ntt,
            num_vars: self.num_vars,
            ntt_table: Rc::new(self.ntt_table.iter().map(|x| EF::from_base(*x)).collect()),
        }
    }
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
/// * u: the random point
/// * ntt_table: It stores the NTT table: ω^0, ω^1, ..., ω^{2N - 1}
pub fn init_fourier_table_overall<F: Field>(u: &[F], ntt_table: &[F]) -> IntermediateMLEs<F> {
    let log_n = u.len(); // N = 1 << dim
    let m = ntt_table.len(); // M = 2N = 2 * (1 << dim)

    // It store the evaluations of all F(u, x) for x \in \{0, 1\}^dim.
    // Note that in our implementation, we use little endian form, so the index `0b1011`
    // represents the point `P(1,1,0,1)` in {0,1}^`dim`
    let mut evaluations: Vec<_> = vec![F::zero(); 1 << log_n];
    evaluations[0] = F::one();

    // stores all the intermediate evaluations of the table (i.e. F(u, x)) and the term ω^{2^{i + 1} * X} in each iteration
    let mut intermediate_mles = <IntermediateMLEs<F>>::new(log_n as u32);

    // * Compute \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
    // The reason why we update the table with u_i in reverse order is that
    // in round i, ω^{2^{i + 1} is the (M / (2^{i+1}))-th root of unity, e.g. i = dim - 1, ω^{2^{i + 1} is the 2-th root of unity.
    // Hence, we need to align this with the update method in dynamic programming.
    //
    // Note that the last term ω^{2^i * x_i} is indeed multiplied in the normal order, from x_0 to x_{log{n-1}}
    // since we actually iterate from the LSB to MSB  when updating the table from size 1, 2, 4, 8, ..., n in dynamic programming.
    // ! Modified Formula
    for (i, u_i) in u.iter().enumerate() {
        // i starts from log_n - 1 and ends to 0
        let this_round_dim = i + 1;
        let last_round_dim = this_round_dim - 1;
        let this_round_table_size = 1 << this_round_dim;
        let last_round_table_size = 1 << last_round_dim;

        let mut evaluations_w_term = vec![F::zero(); this_round_table_size];
        for x in (0..this_round_table_size).rev() {
            // idx is to indicate the power ω^{2^{i + 1} * X} in ntt_table
            // ! Modified Formula
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

    intermediate_mles
}

/// Naive implementation for computing the MLE:
/// compute w_{i+1} (x)= w^{ M / {2^{i+1}}  * X} = w^{ N / 2^i * X}
/// for x \in \{0, 1\}^x_dim in a naive method
///
/// # Arguments:
///
/// * ntt_table: NTT table for w (M-th root of unity) containing {1, w, w^1, ..., w^{M-1}}
/// * log_m: log of M
/// * x_dim: dimension of x or the num of variables of the outputted mle
/// * sub: the exponent of the function defined above (i+1) = x_dim
pub fn naive_w_power_times_x_table<F: Field>(
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
        // ! Modified Formula
        evaluations[x] = ntt_table[(1 << (log_m - sub)) * x % m];
    }
    DenseMultilinearExtension::from_evaluations_vec(x_dim, evaluations)
}

/// Evaluate the mle w_{i+1} (x) for a random point r \in F^{x_dim} where w_{i+1} denotes the 2^{i+1}-th root of unity
/// This formula is also derived from the techniques in [zkCNN](https://eprint.iacr.org/2021/673).
///
/// w_{i+1} (x)= w^{ M / {2^{i+1}} * X} = w^{ N / 2^i * X} for a random point r
///               = \prod_i (1 - r_i + r_i * w_{i+1}^2^i)
///
/// # Arguments:
///
/// * ntt_table: NTT table for w (M-th root of unity) containing {1, w, w^1, ..., w^{M-1}}
/// * log_m: log of M
/// * x_dim: dimension of x or the num of variables of the outputted mle
/// * sub: the subscript of the function defined above (i+1) = x_dim
/// * r: random point in F^{x_dim}
pub fn eval_w_power_times_x<F: Field>(
    ntt_table: &[F],
    log_m: usize,
    x_dim: usize,
    sub: usize,
    r: &[F],
) -> F {
    assert_eq!(ntt_table.len(), 1 << log_m);
    assert_eq!(x_dim, r.len());
    // ! Modified Formula
    assert_eq!(sub, x_dim);
    let mut prod = F::one();

    for (i, &r_i) in r.iter().enumerate() {
        let log_exp = (log_m - sub + i) % log_m;
        prod *= F::one() - r_i + r_i * ntt_table[1 << log_exp];
    }

    prod
}

impl<F: Field> NTTInstance<F> {
    /// Extract the information of the NTT Instance for verification
    #[inline]
    pub fn info(&self) -> NTTInstanceInfo<F> {
        NTTInstanceInfo {
            num_ntt: 1,
            num_vars: self.num_vars,
            ntt_table: Rc::clone(&self.ntt_table),
        }
    }

    /// Construct a new instance from slice
    #[inline]
    pub fn from_slice(
        log_n: usize,
        ntt_table: &Rc<Vec<F>>,
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
            ntt_table: Rc::new(self.ntt_table.iter().map(|x| EF::from_base(*x)).collect()),
            coeffs: Rc::new(self.coeffs.to_ef::<EF>()),
            points: Rc::new(self.points.to_ef::<EF>()),
        }
    }
}

impl<F: Field> NTTInstances<F> {
    /// Construct an empty container
    #[inline]
    pub fn new(num_vars: usize, ntt_table: &Rc<Vec<F>>) -> Self {
        Self {
            num_ntt: 0,
            num_vars,
            ntt_table: Rc::clone(ntt_table),
            coeffs: Vec::new(),
            points: Vec::new(),
        }
    }

    /// Extract the information of the NTT Instance for verification
    #[inline]
    pub fn info(&self) -> NTTInstanceInfo<F> {
        NTTInstanceInfo {
            num_ntt: self.num_ntt,
            num_vars: self.num_vars,
            ntt_table: Rc::clone(&self.ntt_table),
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

    /// Add a ntt instance into the container
    #[inline]
    pub fn add_ntt(
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
        let num_vars_added_half = self.log_num_oracles();
        let num_zeros_padded_half =
            ((1 << num_vars_added_half) - self.num_oracles()) * (1 << self.num_vars);

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
        let num_oracles_half = self.num_ntt;
        let num_vars_added_half = num_oracles_half.next_power_of_two().ilog2() as usize;
        let num_vars = self.num_vars + num_vars_added_half + 1;

        // arrangement: all coeffs || padded zeros || all points || padded zeros
        // The advantage of this arrangement is that F(0, x) packs all evaluations of coeff-MLEs and F(1, x) packs all evaluations of point-MLEs
        let evals = self.pack_all_mles();
        <DenseMultilinearExtension<F>>::from_evaluations_vec(num_vars, evals)
    }

    /// Construct a random ntt instances from all the ntt instances to be proved, with randomness defined over Field
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
            ntt_table: Rc::clone(&self.ntt_table),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }

    /// Construct a random ntt instances from all the ntt instances to be proved, with randomness defined over Extension Field
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
            ntt_table: Rc::new(self.ntt_table.iter().map(|x| EF::from_base(*x)).collect()),
            coeffs: Rc::new(random_coeffs),
            points: Rc::new(random_points),
        }
    }
}

impl<F: Field + Serialize> NTTIOP<F> {
    /// sample the random coins before proving sumcheck protocol
    pub fn sample_coins(trans: &mut Transcript<F>, num_ntt: usize) -> Vec<F> {
        trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            num_ntt,
        )
    }

    /// return the number of coins used in this IOP
    pub fn num_coins(info: &NTTInstanceInfo<F>) -> usize {
        info.num_ntt
    }

    /// Prove NTT instance with delegation
    pub fn prove(instance: &NTTInstance<F>) -> (SumcheckKit<F>, NTTRecursiveProof<F>) {
        let mut trans = Transcript::new();
        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        let mut poly = ListOfProductsOfPolynomials::<F>::new(instance.num_vars);
        let randomness = F::one();
        let mut claimed_sum = F::zero();
        <NTTBareIOP<F>>::prove_as_subprotocol(
            randomness,
            &mut poly,
            &mut claimed_sum,
            instance,
            &u,
        );

        let (proof, state) =
            MLSumcheck::prove(&mut trans, &poly).expect("fail to prove the sumcheck protocol");

        // prove F(u, v) in a recursive manner
        let recursive_proof =
            <NTTIOP<F>>::prove_recursive(&mut trans, &state.randomness, &instance.info(), &u);

        (
            SumcheckKit {
                proof,
                claimed_sum,
                info: poly.info(),
                u,
                randomness: state.randomness,
            },
            recursive_proof,
        )
    }

    /// Verify NTT instance with delegation
    pub fn verify(
        wrapper: &mut ProofWrapper<F>,
        evals_at_r: F,
        evals_at_u: F,
        info: &NTTInstanceInfo<F>,
        recursive_proof: &NTTRecursiveProof<F>,
    ) -> bool {
        let mut trans = Transcript::new();

        let u = trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            info.num_vars,
        );

        let randomness = F::one();

        let mut subclaim = MLSumcheck::verify(
            &mut trans,
            &wrapper.info,
            wrapper.claimed_sum,
            &wrapper.proof,
        )
        .expect("fail to verify the sumcheck protocol");

        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        if !<NTTBareIOP<F>>::verify_as_subprotocol(
            randomness,
            &mut subclaim,
            &mut wrapper.claimed_sum,
            evals_at_r,
            evals_at_u,
            f_delegation,
        ) {
            return false;
        }

        if !(subclaim.expected_evaluations == F::zero() && wrapper.claimed_sum == F::zero()) {
            return false;
        }

        <NTTIOP<F>>::verify_recursive(&mut trans, recursive_proof, info, &u, &subclaim)
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
    /// * `ntt_bare_state`: stores the prover state after proving the NTT bare
    pub fn prove_recursive(
        trans: &mut Transcript<F>,
        ntt_bare_randomness: &[F],
        info: &NTTInstanceInfo<F>,
        u: &[F],
    ) -> NTTRecursiveProof<F> {
        let log_n = info.num_vars;

        let intermediate_mles = init_fourier_table_overall(u, &info.ntt_table);
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
        // ! Modified Formula
        for k in (1..log_n).rev() {
            // start form log_n - 1;
            // let i = log_n - 1 - k;
            delegation_claimed_sums.push(reduced_claim);

            let w_coeff = info.ntt_table[1 << k];
            let f = &f_mles[k - 1];
            let (proof_round, state_round) = Self::delegation_prover_round(
                trans,
                k,
                &requested_point,
                // ! Modified Formula
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
        let log_n = ntt_instance_info.num_vars;
        let ntt_table = &ntt_instance_info.ntt_table;

        // r_left = (r, 0) and r_right = (r, 0)
        let mut r_left: Vec<_> = Vec::with_capacity(round + 1);
        let mut r_right: Vec<_> = Vec::with_capacity(round + 1);
        r_left.extend(&subclaim.point);
        r_right.extend(&subclaim.point);
        r_left.push(F::zero());
        r_right.push(F::one());

        // compute $\ω^{(k)}_{i+1}(x,b ) = \ω^{2^{i+1}\cdot j}$ for $j = X+2^{i+1}\cdot b$ at point (r, 0) and (r, 1)
        // exp: i + 1 = n - k
        // let exp = log_n - round;
        // ! Modified Formula
        let sub = round + 1;
        // w_left = \tilde{ω}^{(k)}_{i+1}(r, 0) and w_right = \tilde{ω}^{(k)}_{i+1}(r, 0)
        let w_left = eval_w_power_times_x(ntt_table, log_n + 1, round + 1, sub, &r_left);
        let w_right = eval_w_power_times_x(ntt_table, log_n + 1, round + 1, sub, &r_right);

        let eval = eval_identity_function(x_b_point, &r_left)
            * reduced_claim
            * (F::one() - u_i + u_i * w_left)
            + eval_identity_function(x_b_point, &r_right)
                * reduced_claim
                * (F::one() - u_i + u_i * w_right)
                * ntt_table[1 << round];

        eval == subclaim.expected_evaluations
    }

    /// Compared to the `prove` functionality, we remove the phase to prove NTT bare.
    /// Also, after detaching the verification of NTT bare, verifier can directly check the recursive proofs.
    pub fn verify_recursive(
        trans: &mut Transcript<F>,
        proof: &NTTRecursiveProof<F>,
        info: &NTTInstanceInfo<F>,
        u: &[F],
        subclaim: &SubClaim<F>,
    ) -> bool {
        let log_n = info.num_vars;
        assert_eq!(proof.delegation_sumcheck_msgs.len(), log_n - 1);
        assert_eq!(proof.delegation_claimed_sums.len(), log_n - 1);

        // 1. [detached] verify a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) } for a random point u
        // Note that the delegated value F(u, v) is stored in proof.delegation_claimed_sums[0].

        // 2. verify the computation of F(u, v) in log_n - 1 rounds
        let mut requested_point = subclaim.point.clone();
        for (cnt, k) in (1..log_n).rev().enumerate() {
            // let i = log_n - 1 - k;

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
                // ! Modified Formula
                u[k],
                &subclaim,
                reduced_claim,
                info,
            ) {
                panic!("ntt verification failed in round {cnt}");
            }
            requested_point = subclaim.point;
        }

        let delegation_final_claim = proof.final_claim;
        let final_point = requested_point;
        // TODO: handle the case that log = 1
        assert_eq!(final_point.len(), 1);

        // check the final claim returned from the last round of delegation
        // ! Modified Formula
        let idx = 1 << (info.num_vars);
        let eval = eval_identity_function(&final_point, &[F::zero()])
            + eval_identity_function(&final_point, &[F::one()])
                * (F::one() - u[0] + u[0] * info.ntt_table[idx])
                * info.ntt_table[1];

        delegation_final_claim == eval
    }
}

impl<F, EF> NTTSnarks<F, EF>
where
    F: Field + Serialize + for<'de> Deserialize<'de>,
    EF: AbstractExtensionField<F> + Serialize + for<'de> Deserialize<'de>,
{
    /// Generate and check snarks
    pub fn snarks<H, C, S>(instance: &NTTInstances<F>, code_spec: &S)
    where
        H: Hash + Sync + Send,
        C: LinearCode<F> + Serialize + for<'de> Deserialize<'de>,
        S: LinearCodeSpec<F, Code = C> + Clone,
    {
        let instance_info = instance.info();
        println!("Prove {instance_info}\n");
        // This is the actual polynomial to be committed for prover, which consists of all the required small polynomials in the IOP and padded zero polynomials.
        let committed_poly = instance.generate_oracle();

        // 1. Use PCS to commit the above polynomial.
        let start = Instant::now();
        let pp =
            BrakedownPCS::<F, H, C, S, EF>::setup(committed_poly.num_vars, Some(code_spec.clone()));
        let setup_time = start.elapsed().as_millis();

        let start = Instant::now();
        let (comm, comm_state) = BrakedownPCS::<F, H, C, S, EF>::commit(&pp, &committed_poly);
        let commit_time = start.elapsed().as_millis();

        // 2. Prover generates the proof
        let prover_start = Instant::now();
        let mut iop_proof_size = 0;
        let mut prover_trans = Transcript::<EF>::new();

        // 2.1 Generate the random point to instantiate the sumcheck protocol
        let prover_u = prover_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance.num_vars,
        );

        // 2.? [one more step] Prover generate the random ntt instance from all instances to be proved
        let prover_r = <NTTIOP<EF>>::sample_coins(&mut prover_trans, instance_info.num_ntt);
        let instance_ef = instance.extract_ntt_instance_to_ef::<EF>(&prover_r);
        let instance_ef_info = instance_ef.info();

        // 2.2 Construct the polynomial and the claimed sum to be proved in the sumcheck protocol
        let mut sumcheck_poly = <ListOfProductsOfPolynomials<EF>>::new(instance.num_vars);
        let mut claimed_sum = EF::zero();
        <NTTBareIOP<EF>>::prove_as_subprotocol(
            EF::one(),
            &mut sumcheck_poly,
            &mut claimed_sum,
            &instance_ef,
            &prover_u,
        );

        let poly_info = sumcheck_poly.info();

        // 2.3 Generate proof of sumcheck protocol
        let (sumcheck_proof, sumcheck_state) =
            <MLSumcheck<EF>>::prove(&mut prover_trans, &sumcheck_poly)
                .expect("Proof generated in Addition In Zq");
        iop_proof_size += bincode::serialize(&sumcheck_proof).unwrap().len();

        // 2.? [one more step] Prover recursive prove the evaluation of F(u, v)
        let recursive_proof = <NTTIOP<EF>>::prove_recursive(
            &mut prover_trans,
            &sumcheck_state.randomness,
            &instance_ef_info,
            &prover_u,
        );
        iop_proof_size += bincode::serialize(&recursive_proof).unwrap().len();
        let iop_prover_time = prover_start.elapsed().as_millis();

        // 2.4 Compute all the evaluations of these small polynomials used in IOP over the random point returned from the sumcheck protocol
        let eq_at_r = gen_identity_evaluations(&sumcheck_state.randomness);
        let eq_at_u = gen_identity_evaluations(&prover_u);
        let coeff_evals_at_r = instance
            .coeffs
            .iter()
            // .map(|x| x.evaluate_ext(&sumcheck_state.randomness))
            .map(|x| x.evaluate_ext_opt(&eq_at_r))
            .collect::<Vec<_>>();
        let point_evals_at_u = instance
            .points
            .iter()
            // .map(|x| x.evaluate_ext(&prover_u))
            .map(|x| x.evaluate_ext_opt(&eq_at_u))
            .collect::<Vec<_>>();

        // 2.5 Reduce the proof of the above evaluations to a single random point over the committed polynomial
        let mut coeff_requested_point = sumcheck_state.randomness.clone();
        let mut point_requested_point = prover_u.clone();
        let oracle_randomness = prover_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        );
        coeff_requested_point.extend(&oracle_randomness);
        point_requested_point.extend(&oracle_randomness);
        coeff_requested_point.push(EF::zero());
        point_requested_point.push(EF::one());

        let oracle_coeff_eval = committed_poly.evaluate_ext(&coeff_requested_point);
        let oracle_point_eval = committed_poly.evaluate_ext(&point_requested_point);

        // 2.6 Generate the evaluation proof of the requested points
        let start = Instant::now();
        // requested point [sumcheck_r, oracle_r, 0]
        let coeff_eval_proof = BrakedownPCS::<F, H, C, S, EF>::open(
            &pp,
            &comm,
            &comm_state,
            &coeff_requested_point,
            &mut prover_trans,
        );
        // requested point [prover_u, oracle_r, 1]
        let point_eval_proof = BrakedownPCS::<F, H, C, S, EF>::open(
            &pp,
            &comm,
            &comm_state,
            &point_requested_point,
            &mut prover_trans,
        );
        let pcs_open_time = start.elapsed().as_millis();

        // 3. Verifier checks the proof
        let verifier_start = Instant::now();
        let mut verifier_trans = Transcript::<EF>::new();

        // 3.1 Generate the random point to instantiate the sumcheck protocol
        let verifier_u = verifier_trans.get_vec_challenge(
            b"random point used to instantiate sumcheck protocol",
            instance_info.num_vars,
        );

        // 3.2 Verifier sample random coins to combine all sumcheck protocols proving ntt instances
        let verifier_r = verifier_trans.get_vec_challenge(
            b"randomness used to obtain the virtual random ntt instance",
            instance_info.num_ntt,
        );

        // 3.3 Check the proof of the sumcheck protocol
        let mut subclaim = <MLSumcheck<EF>>::verify(
            &mut verifier_trans,
            &poly_info,
            claimed_sum,
            &sumcheck_proof,
        )
        .expect("Verify the proof generated in NTT");

        // 3.4 Check the subclaim returned from the sumcheck protocol
        let f_delegation = recursive_proof.delegation_claimed_sums[0];
        let evals_at_r = verifier_r
            .iter()
            .zip(coeff_evals_at_r.iter())
            .fold(EF::zero(), |acc, (r, eval)| acc + *r * *eval);
        let evals_at_u = verifier_r
            .iter()
            .zip(point_evals_at_u.iter())
            .fold(EF::zero(), |acc, (r, eval)| acc + *r * *eval);

        let check_subclaim = <NTTBareIOP<EF>>::verify_as_subprotocol(
            EF::one(),
            &mut subclaim,
            &mut claimed_sum,
            evals_at_r,
            evals_at_u,
            f_delegation,
        );
        assert!(check_subclaim);
        assert_eq!(subclaim.expected_evaluations, EF::zero());
        assert_eq!(claimed_sum, EF::zero());
        // Check the delegation of F(u, v) used in the above check
        let check_recursive = <NTTIOP<EF>>::verify_recursive(
            &mut verifier_trans,
            &recursive_proof,
            &instance_ef_info,
            &verifier_u,
            &subclaim,
        );
        assert!(check_recursive);

        // 3.5 and also check the relation between these small oracles and the committed oracle
        let oracle_randomness = verifier_trans.get_vec_challenge(
            b"random linear combination for evaluations of oracles",
            instance.log_num_oracles(),
        );
        let check_oracle_coeff =
            verify_oracle_relation(&coeff_evals_at_r, oracle_coeff_eval, &oracle_randomness);
        let check_oracle_point =
            verify_oracle_relation(&point_evals_at_u, oracle_point_eval, &oracle_randomness);
        assert!(check_oracle_coeff);
        assert!(check_oracle_point);
        let iop_verifier_time = verifier_start.elapsed().as_millis();

        // 3.5 Check the evaluation of a random point over the committed oracle
        let start = Instant::now();
        let mut pcs_proof_size = 0;
        let check_pcs_coeff = BrakedownPCS::<F, H, C, S, EF>::verify(
            &pp,
            &comm,
            &coeff_requested_point,
            oracle_coeff_eval,
            &coeff_eval_proof,
            &mut verifier_trans,
        );
        let check_pcs_point = BrakedownPCS::<F, H, C, S, EF>::verify(
            &pp,
            &comm,
            &point_requested_point,
            oracle_point_eval,
            &point_eval_proof,
            &mut verifier_trans,
        );
        assert!(check_pcs_coeff);
        assert!(check_pcs_point);
        let pcs_verifier_time = start.elapsed().as_millis();
        pcs_proof_size += bincode::serialize(&coeff_eval_proof).unwrap().len()
            + bincode::serialize(&coeff_evals_at_r).unwrap().len()
            + bincode::serialize(&point_eval_proof).unwrap().len()
            + bincode::serialize(&point_evals_at_u).unwrap().len();

        // 4. print statistic
        print_statistic(
            iop_prover_time + pcs_open_time,
            iop_verifier_time + pcs_verifier_time,
            iop_proof_size + pcs_proof_size,
            iop_prover_time,
            iop_verifier_time,
            iop_proof_size,
            committed_poly.num_vars,
            instance.num_oracles(),
            instance.num_vars,
            setup_time,
            commit_time,
            pcs_open_time,
            pcs_verifier_time,
            pcs_proof_size,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::piop::ntt::{eval_w_power_times_x, naive_w_power_times_x_table};
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

    /// Given an `index` of `len` bits, output a new index where the bits are reversed.
    fn reverse_bits(index: usize, len: usize) -> usize {
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

        // In mix endian, the index for F[i, j] is i + (j << dim)} where
        // F[x_0, x_1, ..., x_{\logN-1} || y_0, y_1, ..., y_{\logN-1}]
        // i = \sum_k 2^k * x_k and j = \sum_k 2^k * y_k
        // rev_i = \sum_k 2^{\logN-1-k} x_k and j = \sum_k 2^k * y_k
        for i in 0..1 << dim {
            for j in 0..1 << dim {
                // ! Modified Formula
                let rev_i = reverse_bits(i, dim);
                let idx_power = ((2 * rev_i + 1) * j) as u32 % m;
                let idx_fourier = i + (j << dim);
                fourier_matrix[idx_fourier] = ntt_table[idx_power as usize];
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
