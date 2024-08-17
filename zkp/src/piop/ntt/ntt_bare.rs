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

use crate::sumcheck::prover::ProverMsg;
use crate::sumcheck::prover::ProverState;
use crate::sumcheck::MLSumcheck;
use std::marker::PhantomData;
use std::rc::Rc;

use super::NTTInstanceExt;
use super::NTTInstanceInfo;
use algebra::utils::Transcript;
use algebra::AbstractExtensionField;
use algebra::DenseMultilinearExtensionBase;
use algebra::{
    DenseMultilinearExtension, Field, ListOfProductsOfPolynomials, MultilinearExtension,
    PolynomialInfo,
};

/// IOP for NTT, i.e. $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
pub struct NTTBareIOP<F: Field, EF: AbstractExtensionField<F>> {
    _marker: PhantomData<F>,
    _stone: PhantomData<EF>,
}

/// proof generated by prover in bare ntt, which only consists of the sumcheck without delegation for F(u, v)
/// Without delegation, prover only needs to prove this sum
/// $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
/// where u is a random point, given by verifier
pub struct NTTBareProof<F: Field, EF: AbstractExtensionField<F>> {
    /// sumcheck_msg when proving
    pub sumcheck_msg: Vec<ProverMsg<F, EF>>,
    /// the claimed sum is a(u)
    pub claimed_sum: EF,
}

/// subclaim returned in bare ntt, which only consists of the sumcheck without delegation for F(u, v)
/// Without delegation, prover only needs to prove this sum
/// $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
/// where u is a random point, given by verifier
pub struct NTTBareSubclaim<F: Field, EF: AbstractExtensionField<F>> {
    /// the claimed sum is a(u)
    pub claimed_sum: EF,
    /// the proof is reduced to the evaluation of this point (denoted by v)
    pub point: Vec<EF>,
    /// the proof is reduced to the evaluation equals to c(v) \cdot F(u, v)
    pub expected_evaluation: EF,
    _marker: PhantomData<F>,
}

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
///   In order to delegate the computation F(u, v) to prover, we decompose the ω^X term into the grand product.
///   Hence, the final equation is = \prod_{i=0}^{\log{N-1}} ((1 - u_i) + u_i * ω^{2^{i + 1} * X}) * ω^{2^i * x_i}
pub fn naive_init_fourier_table<F: Field, EF: AbstractExtensionField<F>>(
    u: &[EF],
    ntt_table: &[F],
) -> DenseMultilinearExtension<F, EF> {
    let log_n = u.len();
    let m = ntt_table.len(); // m = 2n = 2 * (1 << dim)

    let mut evaluations = vec![EF::one(); 1 << log_n];

    for (x, eval_at_x) in evaluations.iter_mut().enumerate() {
        for (i, &u_i) in u.iter().enumerate().take(log_n) {
            let idx = (1 << (i + 1)) * x % m;

            let x_i = (x >> i) & 1;
            let x_i_idx = (1 << i) * x_i;
            *eval_at_x *= ((EF::one() - u_i) + u_i * ntt_table[idx]) * ntt_table[x_i_idx];
        }
    }

    DenseMultilinearExtension::from_evaluations_vec(log_n, evaluations)
}

/// Generate MLE for the Fourier function F(u, x) for x \in \{0, 1\}^dim where u is the random point.
/// Dynamic programming implementaion for initializing F(u, x) in NTT (derived from zkCNN: https://eprint.iacr.org/2021/673)
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
pub fn init_fourier_table<F: Field, EF: AbstractExtensionField<F>>(
    u: &[EF],
    ntt_table: &[F],
) -> DenseMultilinearExtension<F, EF> {
    let log_n = u.len(); // n = 1 << dim
    let m = ntt_table.len(); // m = 2n = 2 * (1 << dim)

    // It store the evaluations of all F(u, x) for x \in \{0, 1\}^dim.
    // Note that in our implementation, we use little endian form, so the index `0b1011`
    // represents the point `P(1,1,0,1)` in {0,1}^`dim`
    let mut evaluations = vec![EF::zero(); 1 << log_n];
    evaluations[0] = EF::one();

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
                    * (EF::one() - u[i] + u[i] * ntt_table[idx])
                    * ntt_table[last_table_size];
            }
            // If bit = 0, we do not need to multiply because ω^{2^k * 0} = 1
            else {
                evaluations[j] =
                    evaluations[j % last_table_size] * (EF::one() - u[i] + u[i] * ntt_table[idx]);
            }
        }
    }
    DenseMultilinearExtension::from_evaluations_vec(log_n, evaluations)
}

impl<F: Field, EF: AbstractExtensionField<F>> NTTBareSubclaim<F, EF> {
    /// verify the subcliam for sumcheck
    /// $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    ///
    /// 1. a(u) = claimed_sum
    /// 2. c(v) * F(u, v) = expected_evaluation
    /// # Arguments
    ///
    /// * fourier_matrix: F(x, y) oracle
    /// * points: a(x) oracle
    /// * coeffs: c(x) oracle
    /// * u: the random point sampled by verifier before executing the sumcheck protocol
    #[inline]
    pub fn verify_subclaim(
        &self,
        fourier_matrix: &DenseMultilinearExtensionBase<F>,
        points: &DenseMultilinearExtension<F, EF>,
        coeffs: &DenseMultilinearExtension<F, EF>,
        u: &[EF],
        info: &NTTInstanceInfo<F>,
    ) -> bool {
        assert_eq!(u.len(), info.log_n);

        // check 1: a(u) = claimed_sum
        if self.claimed_sum != points.evaluate(u) {
            return false;
        }

        // check 2: c(v) * F(u, v) = expected_evaluation
        let mut u_v: Vec<EF> = Vec::with_capacity(info.log_n << 1);
        u_v.extend(u);
        u_v.extend(&self.point);
        self.expected_evaluation == coeffs.evaluate(&self.point) * fourier_matrix.evaluate_ext(&u_v)
    }

    /// verify the subcliam for sumcheck
    /// Compared to the `verify_subcliam`, verify delegate the computation F(u, v) to the prover,
    /// so in this case verify can receives the evaluation F(u, v).
    ///
    /// $$a(u) = \sum_{x\in \{0, 1\}^{\log N} c(x)\cdot F(u, x) }$$
    ///
    /// 1. a(u) = claimed_sum
    /// 2. c(v) * F(u, v) = expected_evaluation
    /// # Arguments
    ///
    /// * f_delegation: F(u, v) computed by prover
    /// * points: a(x) oracle
    /// * coeffs: c(x) oracle
    /// * u: the random point sampled by verifier before executing the sumcheck protocol
    pub fn verify_subclaim_with_delegation(
        &self,
        f_delegation: EF,
        points: &DenseMultilinearExtension<F, EF>,
        coeffs: &DenseMultilinearExtension<F, EF>,
        u: &[EF],
    ) -> bool {
        // check 1: a(u) = claimed_sum
        if self.claimed_sum != points.evaluate(u) {
            return false;
        }

        // check 2: c(v) * F(u, v) = expected_evaluation
        self.expected_evaluation == coeffs.evaluate(&self.point) * f_delegation
    }
}

impl<F: Field, EF: AbstractExtensionField<F>> NTTBareIOP<F, EF> {
    /// prove
    pub fn prove(
        trans: &mut Transcript<F>,
        f_u: &Rc<DenseMultilinearExtension<F, EF>>,
        ntt_instance: &NTTInstanceExt<F, EF>,
        u: &[EF],
    ) -> (NTTBareProof<F, EF>, ProverState<F, EF>) {
        trans.append_message(b"ntt bare", &ntt_instance.info());
        let log_n = ntt_instance.log_n;

        let mut poly = <ListOfProductsOfPolynomials<F, EF>>::new(log_n);

        poly.add_product(
            [
                Rc::clone(f_u),
                // Convert the original MLE over Field to a new MLE over Extension Field
                Rc::new(ntt_instance.coeffs.clone()),
            ],
            EF::one(),
        );

        let (prover_msg, prover_state) =
            MLSumcheck::prove(trans, &poly).expect("ntt bare proof failed");

        (
            NTTBareProof {
                sumcheck_msg: prover_msg,
                claimed_sum: ntt_instance.points.evaluate(u),
            },
            prover_state,
        )
    }

    /// verify
    pub fn verify(
        trans: &mut Transcript<F>,
        ntt_bare_proof: &NTTBareProof<F, EF>,
        ntt_instance_info: &NTTInstanceInfo<F>,
    ) -> NTTBareSubclaim<F, EF> {
        trans.append_message(b"ntt bare", &ntt_instance_info);
        let poly_info = PolynomialInfo {
            max_multiplicands: 2,
            num_variables: ntt_instance_info.log_n,
        };
        let subclaim = MLSumcheck::verify(
            trans,
            &poly_info,
            ntt_bare_proof.claimed_sum,
            &ntt_bare_proof.sumcheck_msg,
        )
        .expect("ntt bare verification failed");

        NTTBareSubclaim {
            claimed_sum: ntt_bare_proof.claimed_sum,
            point: subclaim.point,
            expected_evaluation: subclaim.expected_evaluations,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        derive::{DecomposableField, FheField, Field, Prime, NTT},
        BabyBear, BabyBearExetension, DecomposableField, DenseMultilinearExtensionBase, Field,
        FieldUniformSampler, MultilinearExtension, NTTField,
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
    #[modulus = 2013265921]
    pub struct Fp32(u64);

    // field type
    type FF = BabyBear;
    type EF = BabyBearExetension;

    #[test]
    fn test_naive_init_fourier_matrix() {
        let dim = 2;
        let m = 1 << (dim + 1); // M = 2N = 2 * (1 << dim)
        let u = field_vec!(EF; 1, 1);
        let v = field_vec!(EF; 0, 1);

        let mut u_v: Vec<EF> = Vec::with_capacity(dim << 1);
        u_v.extend(&u);
        u_v.extend(&v);

        // root is the M-th root of unity
        let root = Fp32::try_minimal_primitive_root(m).unwrap();
        let root = FF::new(root.value() as u32);

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

        let fourier_mle =
            DenseMultilinearExtensionBase::from_evaluations_vec(dim << 1, fourier_matrix);
        // It includes the evaluations of f(u, x) for x \in \{0, 1\}^N
        let partial_fourier_mle = naive_init_fourier_table(&u, &ntt_table);

        assert_eq!(
            fourier_mle.evaluate_ext(&u_v),
            partial_fourier_mle.evaluate(&v)
        );
    }

    #[test]
    fn test_init_fourier_matrix() {
        let sampler = <FieldUniformSampler<EF>>::new();
        let mut rng = thread_rng();

        let dim = 10;
        let m = 1 << (dim + 1); // M = 2N = 2 * (1 << dim)
        let u: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();
        let v: Vec<_> = (0..dim).map(|_| sampler.sample(&mut rng)).collect();

        let mut u_v: Vec<EF> = Vec::with_capacity(dim << 1);
        u_v.extend(&u);
        u_v.extend(&v);

        // root is the M-th root of unity
        let root = Fp32::try_minimal_primitive_root(m).unwrap();
        let root = FF::new(root.value() as u32);

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

        let fourier_mle =
            DenseMultilinearExtensionBase::from_evaluations_vec(dim << 1, fourier_matrix);
        // It includes the evaluations of f(u, x) for x \in \{0, 1\}^N
        let partial_fourier_mle = &init_fourier_table(&u, &ntt_table);

        assert_eq!(
            fourier_mle.evaluate_ext(&u_v),
            partial_fourier_mle.evaluate(&v)
        );
    }
}
