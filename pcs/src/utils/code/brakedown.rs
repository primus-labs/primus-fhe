use crate::utils::{
    arithmetic::{ceil, h, SparseMatrixDimension, SparseMatrix},
    code::LinearCode
};

use algebra::{Field, Random};
use std::{
    cmp::{max, min},
    fmt::Debug,
    iter,
    f64
};
use itertools::Itertools;
use rand::RngCore;

// BrakedownCode recursively encodes the message
// For efficiency, we implement iterative version of BrakedownCode

// Specification for BrakedownCode
// Enc: F^n -> F^rn
// A_n = M_{n,alpha*n,c_n}
// B_n = M_{alpha,(r-1-r*alpha)n,d_n}
// the name of the variable is consistent with the paper
pub trait BrakedownSpec: Debug {
    const LAMBDA: f64; // security parameter
    const ALPHA: f64; // column_num/row_num of the random matrix A
    const BETA: f64; // 
    const R: f64; // code rate

    fn delta() -> f64 {
        // relative distance
        Self::BETA / Self::R
    }

    // the soundness error for proximity test consists of two parts (1-delta/3)^num_column_opening and (codeword_len/|F|)^num_proximity_testing
    // to reach required soundness error (security parameter lambda), we compute the needed num_column_opening nad num_proximity_testing

    fn num_column_opening() -> usize {
        ceil(-Self::LAMBDA / (1.0 - Self::delta() / 3.0).log2())
    }

    fn num_proximity_testing(log2_q: usize, n: usize, n_0: usize) -> usize {
        ceil(Self::LAMBDA / (log2_q as f64 - (Self::codeword_len(log2_q, n, n_0) as f64).log2()))
    }

    fn codeword_len(log2_q: usize, n: usize, n_0: usize) -> usize {
        let (a, b) = Self::dimensions(log2_q, n, n_0);
        iter::empty()
            .chain(Some(a[0].n))
            .chain(a[..a.len() - 1].iter().map(|a| a.m))
            .chain(Some(b.last().unwrap().n))
            .chain(b.iter().map(|b| b.m))
            .sum()
    }

    // num of nonzere elements in each row of A_n
    fn c_n(n: usize) -> usize {
        let n = n as f64;
        let alpha = Self::ALPHA;
        let beta = Self::BETA;
        min(
            max(ceil(1.28 * beta * n), ceil(beta * n) + 4),
            ceil(
                ((110.0 / n) + h(beta) + alpha * h(1.28 * beta / alpha))
                    / (beta * (alpha / (1.28 * beta)).log2()),
            ),
        )
    }

    // num of nonzere elements in each row of B_n
    fn d_n(log2_q: usize, n: usize) -> usize {
        let log2_q = log2_q as f64;
        let n = n as f64;
        let alpha = Self::ALPHA;
        let beta = Self::BETA;
        let r = Self::R;
        let mu = Self::R - 1f64 - Self::R * Self::ALPHA; // intermediate value
        let nu = Self::BETA + Self::ALPHA * Self::BETA + 0.03; // intermediate value
        min(
            ceil((2.0 * beta + ((r - 1.0) + 110.0 / n) / log2_q) * n),
            ceil(
                (r * alpha * h(beta / r) + mu * h(nu / mu) + 110.0 / n)
                    / (alpha * beta * (mu / nu).log2()),
            ),
        )
    }

    // at each recursion layer, it needs two matrices A, B

    // we iteratively produce all A, B we need
    // at iteration 1 i.e. the beginning
    // A(n) = M_{n, alpha * n, c_n}
    // B(n) = M_{alpha, (r - 1 - r * alpha) * n, d_n}
    // with M_{n, m, d} denotes row_num, column_num, nonzero_num, respectively

    // at iteration 2
    // n = alpha * n
    // A(n) = ..., B(n) = ..., proceeding like the above

    // iteratively produces matrices A, B until n <= n_0

    // generating dimensions iteratively
    fn dimensions(
        log2_q: usize,
        n: usize,
        n_0: usize,
    ) -> (Vec<SparseMatrixDimension>, Vec<SparseMatrixDimension>) {
        assert!(n > n_0);

        let a = iter::successors(Some(n), |n| Some(ceil(*n as f64 * Self::ALPHA)))
            .tuple_windows()
            .map(|(n, m)| SparseMatrixDimension::new(n, m, min(Self::c_n(n), m)))
            .take_while(|a| a.n > n_0)
            .collect_vec();

        let b = a
            .iter()
            .map(|a| {
                let n_prime = ceil(a.m as f64 * Self::R);
                let m_prime = ceil(a.n as f64 * Self::R) - a.m - n_prime;
                SparseMatrixDimension::new(n_prime, m_prime, min(Self::d_n(log2_q, a.n), m_prime))
            })
            .collect();

        (a, b)
    }

    // generating random matrices iteratively
    fn matrices<F: Field + Random>(
        log2_q: usize,
        n: usize,
        n_0: usize,
        mut rng: impl RngCore,
    ) -> (Vec<SparseMatrix<F>>, Vec<SparseMatrix<F>>) {
        let (a, b) = Self::dimensions(log2_q, n, n_0);
        a.into_iter()
            .zip(b)
            .map(|(a, b)| {
                (
                    SparseMatrix::random(a, &mut rng),
                    SparseMatrix::random(b, &mut rng),
                )
            })
            .unzip()
    }
}

#[derive(Clone, Debug)]
pub struct Brakedown<F> {
    row_len: usize,
    codeword_len: usize,
    num_column_opening: usize,
    num_proximity_testing: usize,
    a: Vec<SparseMatrix<F>>,
    b: Vec<SparseMatrix<F>>,
}

impl<F: Field + Random> Brakedown<F> {

    // c: column_num; r: row_num
    pub fn proof_size<S: BrakedownSpec>(n_0: usize, c: usize, r: usize) -> usize {
        let log2_q = 64; // log_2(MODULAS_INNER) waiting to be sync with Field update
        let num_ldt = S::num_proximity_testing(log2_q, c, n_0);
        (1 + num_ldt) * c + S::num_column_opening() * r
    }

    fn num_column_opening(&self) -> usize {
        self.num_column_opening
    }

    fn num_proximity_testing(&self) -> usize {
        self.num_proximity_testing
    }

    pub fn new_multilinear<S: BrakedownSpec>(
        num_vars: usize,
        n_0: usize,
        rng: impl RngCore,
    ) -> Self {
        assert!(1 << num_vars > n_0);

        let log2_q = 64; // 
        let min_log2_n = (n_0 + 1).next_power_of_two().ilog2() as usize;
        let (_, row_len) =
            (min_log2_n..=num_vars).fold((usize::MAX, 0), |(min_proof_size, row_len), log2_n| {
                let proof_size = Self::proof_size::<S>(n_0, 1 << log2_n, 1 << (num_vars - log2_n));
                if proof_size < min_proof_size {
                    (proof_size, 1 << log2_n)
                } else {
                    (min_proof_size, row_len)
                }
            });
        let codeword_len = S::codeword_len(log2_q, row_len, n_0);
        let num_column_opening = S::num_column_opening();
        let num_proximity_testing = S::num_proximity_testing(log2_q, row_len, n_0);
        let (a, b) = S::matrices(log2_q, row_len, n_0, rng);

        Self {
            row_len,
            codeword_len,
            num_column_opening,
            num_proximity_testing,
            a,
            b,
        }
    }
}

impl<F: Field + Random> LinearCode<F> for Brakedown<F> {

    fn message_len(&self) -> usize {
        self.row_len
    }

    fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    // iteratively encode
    // Enc: x0 -> x0 = x0 | x1 = x*A | x2 = x*A^2| x3 = x*A^3| ... | x_{k-1} = x*A^{k-1} | x_k = ReedSoloman(x*A^k) | x_{k+1} = x_k*B | x_{k+2} = (x_{k-1}|x_k|x_{k+1})*B | x_{k+3} =  (x_{k-2}|x_{k-1}|x_k|x_{k+1}|x_{k+2})*B | ...
    // all A, B above are different!
    // A, B are stored in self.a, self.b
    fn encode(&self, mut target: impl AsMut<[F]>) {
        // target[0..message_len] is the message
        // target has the length of codeword_len 
        let target = target.as_mut();
        assert_eq!(target.len(), self.codeword_len);

        // compute x1 = x*A | x2 = x*A^2| x3 = x*A^3| ... | x_{k-1} = x*A^{k-1}
        let mut input_offset = 0;
        self.a[..self.a.len() - 1].iter().for_each(|a| {
            let (input, output) = target[input_offset..].split_at_mut(a.dimension.n);
            a.dot_into(input, &mut output[..a.dimension.m]);
            input_offset += a.dimension.n;
        });

        // compute x_k = ReedSoloman(x*A^k)
        let a_last = self.a.last().unwrap();
        let b_last = self.b.last().unwrap();
        let (input, output) = target[input_offset..].split_at_mut(a_last.dimension.n);
        let tmp = a_last.dot(input);
        reed_solomon_into(&tmp, &mut output[..b_last.dimension.n]);
        let mut output_offset = input_offset + a_last.dimension.n + b_last.dimension.n;
        input_offset += a_last.dimension.n + a_last.dimension.m;

        // compute x_{k+1} = x_k*B | x_{k+2} = (x_{k-1}|x_k|x_{k+1})*B | x_{k+3} =  (x_{k-2}|x_{k-1}|x_k|x_{k+1}|x_{k+2})*B | ...
        self.a
            .iter()
            .rev()
            .zip(self.b.iter().rev())
            .for_each(|(a, b)| {
                input_offset -= a.dimension.m;
                let (input, output) = target.split_at_mut(output_offset);
                b.dot_into(
                    &input[input_offset..input_offset + b.dimension.n],
                    &mut output[..b.dimension.m],
                );
                output_offset += b.dimension.m;
            });

        
        assert_eq!(input_offset, self.a[0].dimension.n);
        assert_eq!(output_offset, target.len());
    
    }
}

fn reed_solomon_into<F: Field>(input: &[F], mut target: impl AsMut<[F]>) {
    target
        .as_mut()
        .iter_mut()
        .zip(steps(F::ONE))
        .for_each(|(target, x)| *target = evaluate(input, &x));
}

// evaluate the polynomial of coeffs at the point x
pub fn evaluate<F: Field>(coeffs: &[F], x: &F) -> F {
    coeffs
        .iter()
        .rev()
        .fold(F::ZERO, |acc, coeff| acc * x + coeff)
}

pub fn steps<F: Field>(start: F) -> impl Iterator<Item = F> {
    iter::successors(Some(start), move |state| Some(F::ONE + state))
}

macro_rules! impl_spec_128 {
    ($(($name:ident, $alpha:literal, $beta:literal, $r:literal)),*) => {
        $(
            #[derive(Debug)]
            pub struct $name;
            impl BrakedownSpec for $name {
                const LAMBDA: f64 = 128.0;
                const ALPHA: f64 = $alpha;
                const BETA: f64 = $beta;
                const R: f64 = $r;
            }
        )*
    };
}

// Figure 2 in [GLSTW21](https://eprint.iacr.org/2021/1043.pdf).
impl_spec_128!(
    (BrakedownSpec1, 0.1195, 0.0284, 1.420),
    (BrakedownSpec2, 0.1380, 0.0444, 1.470),
    (BrakedownSpec3, 0.1780, 0.0610, 1.521),
    (BrakedownSpec4, 0.2000, 0.0820, 1.640),
    (BrakedownSpec5, 0.2110, 0.0970, 1.616),
    (BrakedownSpec6, 0.2380, 0.1205, 1.720)
);


#[cfg(test)]
mod test {
    use crate::utils::code::{
        Brakedown,
        BrakedownSpec, BrakedownSpec1, BrakedownSpec2, BrakedownSpec3, BrakedownSpec4,
        BrakedownSpec5, BrakedownSpec6, LinearCode,
    };
    use algebra::{derive::*, Field};

    fn assert_spec_correct<S: BrakedownSpec>(
        log2_q: usize,
        delta: f64,
        c_n: usize,
        d_n: usize,
        num_column_opening: usize,
        num_proximity_testing: usize,
    ) {
        let n = 1 << 30;
        let n_0 = 30;
        assert!(S::delta() - delta < 1e-3);
        assert_eq!(S::c_n(n), c_n);
        assert_eq!(S::d_n(log2_q, n), d_n);
        assert_eq!(S::num_column_opening(), num_column_opening);
        assert_eq!(
            S::num_proximity_testing(log2_q, n, n_0),
            num_proximity_testing
        );
    }

    #[test]
    fn spec_127_bit_field() {
        assert_spec_correct::<BrakedownSpec1>(127, 0.02,  6, 33, 13265, 2);
        assert_spec_correct::<BrakedownSpec2>(127, 0.03,  7, 26,  8768, 2);
        assert_spec_correct::<BrakedownSpec3>(127, 0.04,  7, 22,  6593, 2);
        assert_spec_correct::<BrakedownSpec4>(127, 0.05,  8, 19,  5279, 2);
        assert_spec_correct::<BrakedownSpec5>(127, 0.06,  9, 21,  4390, 2);
        assert_spec_correct::<BrakedownSpec6>(127, 0.07, 10, 20,  3755, 2);
    }

    #[test]
    fn spec_254_bit_field() {
        assert_spec_correct::<BrakedownSpec1>(254, 0.02,  6, 33, 13265, 1);
        assert_spec_correct::<BrakedownSpec2>(254, 0.03,  7, 26,  8768, 1);
        assert_spec_correct::<BrakedownSpec3>(254, 0.04,  7, 22,  6593, 1);
        assert_spec_correct::<BrakedownSpec4>(254, 0.05,  8, 19,  5279, 1);
        assert_spec_correct::<BrakedownSpec5>(254, 0.06,  9, 21,  4390, 1);
        assert_spec_correct::<BrakedownSpec6>(254, 0.07, 10, 20,  3755, 1);
    }

    #[derive(Field, Random, Prime, NTT)]
    #[modulus = 132120577]
    pub struct FF(u64);

    #[test]
    fn print_codeword(){

        let rng = rand::thread_rng();
        let brakedown: Brakedown<FF> = Brakedown::new_multilinear::<BrakedownSpec1>(8, 10, rng);

        let mut rng = rand::thread_rng();
        let mut target = vec![FF::random(&mut rng); brakedown.codeword_len()];
        
        brakedown.encode(&mut target);
        target.iter().for_each(|item| println!("{}", item.get()));
    }
}
