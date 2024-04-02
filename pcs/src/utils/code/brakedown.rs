use crate::utils::{
    arithmetic::{ceil, h, SparseMatrix, SparseMatrixDimension},
    code::{LinearCode, ReedSolomonCode},
};

use algebra::{Field, Random};
use itertools::Itertools;
use rand::RngCore;
use std::{
    cmp::{max, min},
    f64,
    fmt::Debug,
    iter,
};

/// BrakedownCode Specification
/// names of the parameters are consistent with the paper
#[derive(Clone, Debug)]
pub struct BrakedownCodeSpec {
    // security parameter
    lambda: f64,
    // code parameter
    alpha: f64,
    beta: f64,
    r: f64,
    field_size_bits: usize,     // log_2(|F|)
    recursion_threshold: usize, // for message_len < recursion threshold, call ReedSolomanCode
    // code property
    distance: f64, // relative distance of the code
    rate: f64, // ideal code rate. the real code rate is message_len/codeword_len, considering error of float points' computation
}

impl BrakedownCodeSpec {
    /// create an instance of BrakedownCodeSpec
    pub fn new(
        lambda: f64,
        alpha: f64,
        beta: f64,
        r: f64,
        field_size_bits: usize,
        recursion_threshold: usize,
    ) -> Self {
        let rate = 1f64 / r;
        let distance = beta / r;
        assert!(0f64 < rate && rate < 1f64);
        assert!(0f64 < distance && distance < 1f64);
        assert!(0f64 < alpha && alpha < 1f64);
        assert!(1.28 * beta < alpha);
        assert!((1f64 - alpha) * r > (1f64 + 2f64 * beta));
        Self {
            lambda,
            alpha,
            beta,
            r,
            field_size_bits,
            recursion_threshold,
            distance,
            rate,
        }
    }

    /// the soundness error specified by the security parameter for proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
    /// return the number of columns needed to open, which accounts for the (1-delta/3)^num_opening part
    pub fn num_opening(&self) -> usize {
        println!("lambda: {}", self.lambda);
        println!("lambda: {}", self.distance);
        ceil(-self.lambda / (1.0 - self.distance / 3.0).log2())
    }

    /// the soundness error specified by the security parameter for proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
    /// return the needed size of the extension field, which accounts for the (codeword_len/|F|) part
    pub fn extension_field_size(&self, message_len: usize) -> usize {
        let n = message_len;
        self.codeword_len(n) * ceil(f64::powf(2f64, self.lambda))
    }

    /// return the codeword length of the given message length under this set of code parameters
    pub fn codeword_len(&self, message_len: usize) -> usize {
        let (a, b) = self.dimensions(message_len);
        message_len + // the systematic part
        a[..a.len()-1].iter().map(|a| a.m).sum::<usize>() + // the upper part (the last a.m is consumed by Reedsolomon code)
        b.last().unwrap().n +// the Reedsolomon code length
        b.iter().map(|b| b.m).sum::<usize>() // the lower part
    }

    /// returh the number of nonzere elements in each row of A_n
    fn c_n(&self, message_len: usize) -> usize {
        let n = message_len as f64;
        let alpha = self.alpha;
        let beta = self.beta;
        min(
            max(ceil(1.28 * beta * n), ceil(beta * n) + 4),
            ceil(
                ((110.0 / n) + h(beta) + alpha * h(1.28 * beta / alpha))
                    / (beta * (alpha / (1.28 * beta)).log2()),
            ),
        )
    }

    /// num of nonzere elements in each row of B_n
    fn d_n(&self, message_len: usize) -> usize {
        let log2_q = self.field_size_bits as f64;
        let n = message_len as f64;
        let alpha = self.alpha;
        let beta = self.beta;
        let r = self.r;
        let mu = r - 1f64 - r * alpha; // intermediate value
        let nu = beta + alpha * beta + 0.03; // intermediate value
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
        &self,
        message_len: usize,
    ) -> (Vec<SparseMatrixDimension>, Vec<SparseMatrixDimension>) {
        let n = message_len;
        let n0 = self.recursion_threshold;
        assert!(n > n0);

        let a = iter::successors(Some(n), |n| Some(ceil(*n as f64 * self.alpha)))
            .tuple_windows()
            .map(|(n, m)| SparseMatrixDimension::new(n, m, min(self.c_n(n), m)))
            .take_while(|a| a.n > n0)
            .collect_vec();

        let b = a
            .iter()
            .map(|a| {
                let n_prime = ceil(a.m as f64 * self.rate);
                let m_prime = ceil(a.n as f64 * self.rate) - a.m - n_prime;
                SparseMatrixDimension::new(n_prime, m_prime, min(self.d_n(a.n), m_prime))
            })
            .collect();

        (a, b)
    }

    // generating random matrices iteratively
    fn matrices<F: Field + Random>(
        &self,
        message_len: usize,
        mut rng: impl RngCore,
    ) -> (Vec<SparseMatrix<F>>, Vec<SparseMatrix<F>>) {
        let (a, b) = self.dimensions(message_len);
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

/// BrakedownCode is linear-time encodable code, using a recursive encoding method in spirit
/// This implementation uses an equavailent iterative encoding method for efficiency
#[derive(Clone, Debug)]
pub struct BrakedownCode<F> {
    spec: BrakedownCodeSpec,
    message_len: usize,
    codeword_len: usize,
    num_opening: usize,
    a: Vec<SparseMatrix<F>>,
    b: Vec<SparseMatrix<F>>,
}

impl<F: Field + Random> BrakedownCode<F> {
    /// create an instance of BrakedownCode
    pub fn new(
        spec: BrakedownCodeSpec,
        num_vars: usize,
        message_len: usize,
        rng: impl RngCore,
    ) -> Self {
        assert!(1 << num_vars > spec.recursion_threshold);

        let (a, b) = spec.matrices(message_len, rng);
        let codeword_len = spec.codeword_len(message_len);
        let num_opening = spec.num_opening();
        Self {
            spec,
            message_len,
            codeword_len,
            num_opening,
            a,
            b,
        }
    }

    /// return the size of proof given column_num c and row_num r, which consists of
    /// product of random vector and commited matrix: 1*c
    /// random selected columns of commited matrix: self.spec.num_opening() * r
    pub fn proof_size(&self, c: usize, r: usize) -> usize {
        c + self.num_opening * r
    }

    /// return the number of column needed to open
    pub fn num_opening(&self) -> usize {
        self.spec.num_opening()
    }

    /// return the needed size of the extension field
    pub fn extension_field_size(&self) -> usize {
        self.spec.extension_field_size(self.message_len)
    }
}

impl<F: Field + Random> LinearCode<F> for BrakedownCode<F> {
    fn message_len(&self) -> usize {
        self.message_len
    }

    fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    // iteratively encode
    // Enc: x0 -> x0 = x0 | x1 = x0 * A0 | x2 = x1 * A1 | x3 = x3 * A3 | ... | x{k-1} = x{k-2} * A{k-1} |
    //            xk = ReedSoloman(x * Ak) |
    //            x{k+1} = xk * B | x_{k+2} = (x_{k-1}|x_k|x_{k+1})*B | x_{k+3} =  (x_{k-2}|x_{k-1}|x_k|x_{k+1}|x_{k+2})*B | ...
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

        a_last.dot_into(input, &mut output[..a_last.dimension.m]);
        let reedsolomon_code = ReedSolomonCode::new(a_last.dimension.m, b_last.dimension.n);
        reedsolomon_code.encode(&mut output[..b_last.dimension.n]);

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

#[cfg(test)]
mod test {
    use crate::utils::code::{BrakedownCode, BrakedownCodeSpec, LinearCode};
    use algebra::{derive::*, Field};

    fn assert_spec_correct(
        spec: BrakedownCodeSpec,
        distance: f64,
        c_n: usize,
        d_n: usize,
        num_opening: usize,
    ) {
        let n = 1 << 30;
        assert!(spec.distance - distance < 1e-3);
        assert_eq!(spec.c_n(n), c_n);
        assert_eq!(spec.d_n(n), d_n);
        assert_eq!(spec.num_opening(), num_opening);
    }

    // Figure 2 in [GLSTW21](https://eprint.iacr.org/2021/1043.pdf).
    #[test]
    fn spec_127_bit_field() {
        let spec1 = BrakedownCodeSpec::new(128.0, 0.1195, 0.0284, 1.420, 127, 30);
        assert_spec_correct(spec1, 0.02, 6, 33, 13265);

        let spec2 = BrakedownCodeSpec::new(128.0, 0.1380, 0.0444, 1.470, 127, 30);
        assert_spec_correct(spec2, 0.03, 7, 26, 8768);

        let spec3 = BrakedownCodeSpec::new(128.0, 0.1780, 0.0610, 1.521, 127, 30);
        assert_spec_correct(spec3, 0.04, 7, 22, 6593);

        let spec4 = BrakedownCodeSpec::new(128.0, 0.2000, 0.0820, 1.640, 127, 30);
        assert_spec_correct(spec4, 0.05, 8, 19, 5279);

        let spec5 = BrakedownCodeSpec::new(128.0, 0.2110, 0.0970, 1.616, 127, 30);
        assert_spec_correct(spec5, 0.06, 9, 21, 4390);

        let spec6 = BrakedownCodeSpec::new(128.0, 0.2380, 0.1205, 1.720, 1, 30);
        assert_spec_correct(spec6, 0.07, 10, 20, 3755);
    }

    #[derive(Field, Random)]
    #[modulus = 32] // pow(2,32)
    pub struct FF32(u64);

    #[test]
    fn print() {
        let rng = rand::thread_rng();
        let spec = BrakedownCodeSpec::new(127.0, 0.1195, 0.0284, 1.420, 31, 5);
        let brakedown_code = BrakedownCode::new(spec, 10, 300, rng);

        // input your message here
        let mut target = vec![FF32::ONE; brakedown_code.codeword_len()];
        println!("message_len: {}", brakedown_code.message_len);
        println!(
            "ideal_codeword_len: {}",
            brakedown_code.message_len as f64 / brakedown_code.spec.rate
        );
        println!("codeword_len: {}", brakedown_code.codeword_len);
        let (a_dimension, b_dimension) = brakedown_code.spec.dimensions(brakedown_code.message_len);
        a_dimension
            .iter()
            .for_each(|a_d| println!("a dimension: {:?}", a_d));
        b_dimension
            .iter()
            .for_each(|b_d| println!("b dimension: {:?}", b_d));
        let (a, b) = (&brakedown_code.a, &brakedown_code.b);
        a.iter().for_each(|a| println!("a matrix: {:?}/n", a));
        b.iter().for_each(|b| println!("b matrix: {:?}/n", b));
        brakedown_code.encode(&mut target);
        target.iter().for_each(|item| println!("{}", item.get()));
    }
}
