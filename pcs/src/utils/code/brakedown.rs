use crate::utils::{
    arithmetic::{ceil, entropy, SparseMatrix, SparseMatrixDimension},
    code::{LinearCode, ReedSolomonCode},
};

use algebra::Field;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::{
    cmp::{max, min},
    f64,
    fmt::Debug,
    iter,
};

/// BrakedownCode Specification
///
/// names of the parameters are consistent with the paper
#[derive(Clone, Debug, Default)]
pub struct BrakedownCodeSpec {
    /// security parameter
    lambda: usize,

    // code parameter
    alpha: f64,
    beta: f64,
    /// inversion of ideal code rate
    r: f64,
    /// log_2(|F|)
    field_size_bits: usize,
    /// for message_len < recursion threshold, call ReedSolomanCode   
    recursion_threshold: usize,

    // code property
    /// relative distance of the code
    distance: f64,
    /// ideal code rate,
    /// the real code rate is message_len/codeword_len, considering error of float points' computation
    rate: f64,
}

impl BrakedownCodeSpec {
    /// create an instance of BrakedownCodeSpec
    #[inline]
    pub fn new(
        lambda: usize,
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

    /// return field_size_bits
    #[inline]
    pub fn field_size_bits(&self) -> usize {
        self.field_size_bits
    }

    /// return recursion_threshold
    #[inline]
    pub fn recursion_threshold(&self) -> usize {
        self.recursion_threshold
    }

    /// the soundness error specified by the security parameter for proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
    /// return the number of columns needed to open, which accounts for the (1-delta/3)^num_opening part
    #[inline]
    pub fn num_queries(&self) -> usize {
        ceil(-(self.lambda as f64) / (1.0 - self.distance / 3.0).log2())
    }

    /// the soundness error specified by the security parameter for proximity test: (1-delta/3)^num_opening + (codeword_len/|F|)
    /// return the needed size of the extension field, which accounts for the (codeword_len/|F|) part
    #[inline]
    pub fn extension_field_size(&self, message_len: usize) -> usize {
        let n = message_len;
        self.codeword_len(n) * ceil(f64::powf(2f64, self.lambda as f64))
    }

    /// return the size of proof given column_num c and row_num r, which consists of the following two parts:
    /// size of the product of random vector and commited matrix: 1*c
    /// size of the random selected columns of commited matrix: self.spec.num_opening() * r
    #[inline]
    pub fn proof_size(&self, c: usize, r: usize) -> usize {
        c + self.num_queries() * r
    }

    /// find the message_len that has optimal proof size, given num_vars
    #[inline]
    pub fn optimize_message_len(&self, num_vars: usize) -> usize {
        let log_threshold = (self.recursion_threshold + 1).next_power_of_two().ilog2() as usize;
        // iterate over (proof_size, message_len/row_len) to find optimal message-len
        (log_threshold..=num_vars)
            .fold(
                (usize::MAX, 0_usize),
                |(min_proof_size, row_len), log_row_len| {
                    let proof_size =
                        self.proof_size(1 << log_row_len, 1 << (num_vars - log_row_len));
                    if proof_size < min_proof_size {
                        (proof_size, 1 << log_row_len)
                    } else {
                        (min_proof_size, row_len)
                    }
                },
            )
            .1
    }

    /// return the codeword length of the given message length under this set of code parameters
    #[inline]
    pub fn codeword_len(&self, message_len: usize) -> usize {
        let (a, b) = self.dimensions(message_len);
        // the systematic part
        message_len +
        // the upper part (the last a.m is consumed by Reedsolomon code)
        a[..a.len()-1].iter().map(|a| a.column_num).sum::<usize>() +
        // the Reedsolomon code length
        b.last().unwrap().row_num +
        // the lower part
        b.iter().map(|b| b.column_num).sum::<usize>()
    }

    /// returh the number of nonzere elements in each row of A_n
    #[inline]
    fn c_n(&self, message_len: usize) -> usize {
        let n = message_len as f64;
        let alpha = self.alpha;
        let beta = self.beta;
        min(
            max((1.28 * beta * n).ceil() as usize, ceil(beta * n) + 4),
            ceil(
                ((110.0 / n) + entropy(beta) + alpha * entropy(1.28 * beta / alpha))
                    / (beta * (alpha / (1.28 * beta)).log2()),
            ),
        )
    }

    /// num of nonzere elements in each row of B_n
    #[inline]
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
                (r * alpha * entropy(beta / r) + mu * entropy(nu / mu) + 110.0 / n)
                    / (alpha * beta * (mu / nu).log2()),
            ),
        )
    }

    /// at each recursion layer, it needs two matrices A, B

    /// we iteratively produce all A, B we need
    /// at iteration 1 i.e. the beginning
    /// A(n) = M_{n, alpha * n, c_n}
    /// B(n) = M_{alpha * r * n, (r - 1 - r * alpha) * n, d_n}
    /// with M_{n, m, d} denotes row_num, column_num, nonzero_num, respectively

    /// at iteration 2
    /// n = alpha * n
    /// A(n) = ..., B(n) = ..., proceeding like the above

    /// iteratively produces matrices A, B until n <= n_0

    /// generating dimensions iteratively
    #[inline]
    fn dimensions(
        &self,
        message_len: usize,
    ) -> (Vec<SparseMatrixDimension>, Vec<SparseMatrixDimension>) {
        let n = message_len;
        let n0 = self.recursion_threshold;
        assert!(n > n0);

        let a = iter::successors(Some(n), |n| Some(ceil(*n as f64 * self.alpha)))
            .tuple_windows()
            .take_while(|(n, _)| n > &n0)
            .map(|(n, m)| SparseMatrixDimension::new(n, m, min(self.c_n(n), m)))
            .collect_vec();

        let b = a
            .iter()
            .map(|a| {
                let n_prime = ceil(a.column_num as f64 * self.rate);
                let m_prime = ceil(a.row_num as f64 * self.rate) - a.column_num - n_prime;
                SparseMatrixDimension::new(n_prime, m_prime, min(self.d_n(a.row_num), m_prime))
            })
            .collect();

        (a, b)
    }

    /// generating random matrices iteratively
    #[inline]
    fn matrices<F: Field>(
        &self,
        message_len: usize,
        mut rng: impl Rng + CryptoRng,
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
///
/// This implementation uses an equavailent iterative encoding method for efficiency
#[derive(Clone, Debug, Default)]
pub struct BrakedownCode<F> {
    /// specification
    pub spec: BrakedownCodeSpec,
    message_len: usize,
    codeword_len: usize,
    num_opening: usize,
    a: Vec<SparseMatrix<F>>,
    b: Vec<SparseMatrix<F>>,
}

impl<F: Field> BrakedownCode<F> {
    /// create an instance of BrakedownCode
    #[inline]
    pub fn new(spec: BrakedownCodeSpec, message_len: usize, rng: impl Rng + CryptoRng) -> Self {
        //assert!(1 << num_vars > spec.recursion_threshold);

        let (a, b) = spec.matrices(message_len, rng);
        let codeword_len = spec.codeword_len(message_len);
        let num_opening = spec.num_queries();
        Self {
            spec,
            message_len,
            codeword_len,
            num_opening,
            a,
            b,
        }
    }

    /// return the size of proof given column_num c and row_num r, which consists of the following two parts:
    /// size of the product of random vector and commited matrix: 1*c
    /// size of the random selected columns of commited matrix: self.spec.num_opening() * r
    #[inline]
    pub fn proof_size(&self, c: usize, r: usize) -> usize {
        c + self.num_opening * r
    }

    /// return the number of column needed to open
    #[inline]
    pub fn num_queries(&self) -> usize {
        min(self.spec.num_queries(), self.message_len)
    }

    /// return the needed size of the extension field
    #[inline]
    pub fn extension_field_size(&self) -> usize {
        self.spec.extension_field_size(self.message_len)
    }
}

impl<F: Field> LinearCode<F> for BrakedownCode<F> {
    #[inline]
    fn message_len(&self) -> usize {
        self.message_len
    }

    #[inline]
    fn codeword_len(&self) -> usize {
        self.codeword_len
    }

    #[inline]
    fn distance(&self) -> f64 {
        self.spec.distance
    }

    /// iteratively encode
    /// Enc(x_0) = x_0 | x_1 | ... | x_{k-1} | x_k | x_{k+1} | ... | x_l
    /// where
    /// \forall 0 <= i < k-1, x_{i+1} = x_i * A_i
    /// \forall 0 <= i < l-k-1, x_{k+i+1} = ( x_{k-i} |...| x_{k+i} ) * B_{l-k-i}
    /// x_k = ReedSolomanCode

    fn encode(&self, mut target: impl AsMut<[F]>) {
        // target[0..message_len] is the message
        // target has the length of codeword_len
        let target = target.as_mut();
        assert_eq!(target.len(), self.codeword_len);

        // compute x1 = x*A | x2 = x*A^2| x3 = x*A^3| ... | x_{k-1} = x*A^{k-1}
        let mut input_offset = 0;
        self.a[..self.a.len() - 1].iter().for_each(|a| {
            let (input, output) = target[input_offset..].split_at_mut(a.dimension.row_num);
            a.multiply_vector(input, &mut output[..a.dimension.column_num]);
            input_offset += a.dimension.row_num;
        });

        // compute x_k = ReedSoloman(x*A^k)
        let a_last = self.a.last().unwrap();
        let b_last = self.b.last().unwrap();

        let (input, output) = target[input_offset..].split_at_mut(a_last.dimension.row_num);

        a_last.multiply_vector(input, &mut output[..a_last.dimension.column_num]);
        let reedsolomon_code =
            ReedSolomonCode::new(a_last.dimension.column_num, b_last.dimension.row_num);
        reedsolomon_code.encode(&mut output[..b_last.dimension.row_num]);

        let mut output_offset = input_offset + a_last.dimension.row_num + b_last.dimension.row_num;
        input_offset += a_last.dimension.row_num + a_last.dimension.column_num;

        // compute x_{k+1} = x_k*B | x_{k+2} = (x_{k-1}|x_k|x_{k+1})*B | x_{k+3} =  (x_{k-2}|x_{k-1}|x_k|x_{k+1}|x_{k+2})*B | ...
        self.a
            .iter()
            .rev()
            .zip(self.b.iter().rev())
            .for_each(|(a, b)| {
                input_offset -= a.dimension.column_num;
                let (input, output) = target.split_at_mut(output_offset);
                b.multiply_vector(
                    &input[input_offset..input_offset + b.dimension.row_num],
                    &mut output[..b.dimension.column_num],
                );
                output_offset += b.dimension.column_num;
            });

        assert_eq!(input_offset, self.a[0].dimension.row_num);
        assert_eq!(output_offset, target.len());
    }
}

#[cfg(test)]
mod test {

    use crate::utils::code::{BrakedownCode, BrakedownCodeSpec, LinearCode};
    use algebra::{derive::*, Field, FieldUniformSampler};
    use rand::Rng;

    /// test whether a set of parameters is correct
    fn assert_spec_correct(
        spec: BrakedownCodeSpec,
        distance: f64,
        c_n: usize,
        d_n: usize,
        num_queries: usize,
    ) {
        let n = 1 << 30;
        assert!(spec.distance - distance < 1e-3);
        assert_eq!(spec.c_n(n), c_n);
        assert_eq!(spec.d_n(n), d_n);
        assert_eq!(spec.num_queries(), num_queries);
    }

    ///  test correctness of sets of parameters taken from Figure 2 in [GLSTW21](https://eprint.iacr.org/2021/1043.pdf).
    #[test]
    fn spec_127_bit_field() {
        let spec1 = BrakedownCodeSpec::new(128, 0.1195, 0.0284, 1.420, 127, 30);
        assert_spec_correct(spec1, 0.02, 6, 33, 13265);

        let spec2 = BrakedownCodeSpec::new(128, 0.1380, 0.0444, 1.470, 127, 30);
        assert_spec_correct(spec2, 0.03, 7, 26, 8768);

        let spec3 = BrakedownCodeSpec::new(128, 0.1780, 0.0610, 1.521, 127, 30);
        assert_spec_correct(spec3, 0.04, 7, 22, 6593);

        let spec4 = BrakedownCodeSpec::new(128, 0.2000, 0.0820, 1.640, 127, 30);
        assert_spec_correct(spec4, 0.05, 8, 19, 5279);

        let spec5 = BrakedownCodeSpec::new(128, 0.2110, 0.0970, 1.616, 127, 30);
        assert_spec_correct(spec5, 0.06, 9, 21, 4390);

        let spec6 = BrakedownCodeSpec::new(128, 0.2380, 0.1205, 1.720, 1, 30);
        assert_spec_correct(spec6, 0.07, 10, 20, 3755);
    }

    #[derive(Field)]
    #[modulus = 32]
    pub struct FF32(u64);

    #[test]
    fn print() {
        let rng = rand::thread_rng();
        let spec = BrakedownCodeSpec::new(127, 0.1195, 0.0284, 1.420, 31, 5);
        let brakedown_code = BrakedownCode::new(spec, 300, rng);

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

    /// test the real code distance is larger or equal to the ideal minimum code distance
    /// two random codewords have large distance to each other with high probability, making it inefficient to find two closed codewords
    /// the test iteratively adds 1 to the first element of the message and compare its codeword to the original codeword
    #[test]
    fn code_distance_test() {
        let mut rng = rand::thread_rng();
        let field_distr = FieldUniformSampler::new();

        let spec = BrakedownCodeSpec::new(128, 0.1195, 0.0284, 1.420, 31, 30);
        let brakedown_code: BrakedownCode<FF32> = BrakedownCode::new(spec, 5000, &mut rng);

        let message_len = brakedown_code.message_len;
        let codeword_len = brakedown_code.codeword_len;

        println!(
            "{:?}\nmessage_len: {}\ncodeword: {}",
            brakedown_code.spec, message_len, codeword_len
        );

        let mut target_0 = vec![FF32::ZERO; codeword_len];
        target_0[..message_len]
            .iter_mut()
            .for_each(|x| *x = rng.sample(field_distr));
        let mut target_1 = target_0.clone();

        let check_times = 32;
        for _ in 0..check_times {
            target_1[0] += FF32::ONE;

            brakedown_code.encode(&mut target_0);
            brakedown_code.encode(&mut target_1);

            let num_real: usize = target_0
                .iter()
                .zip(target_1.iter())
                .map(|(x_0, x_1)| (x_0 != x_1) as usize)
                .sum();
            let num_expected = (brakedown_code.spec.distance * codeword_len as f64) as usize;
            println!(
                "different entries: real num {}, expected num {}",
                num_real, num_expected
            );
            assert!(num_real >= num_expected);
        }
    }

    /// test whether the code is linear
    /// the test compares Enc(k1 * m1 + k2 * m2) and k1 * Enc(m1) + k2 * Enc(m2)
    #[test]
    fn linearity_check() {
        let mut rng = rand::thread_rng();
        let field_distr = FieldUniformSampler::new();

        let spec = BrakedownCodeSpec::new(128, 0.1195, 0.0284, 1.420, 31, 30);
        let brakedown_code: BrakedownCode<FF32> = BrakedownCode::new(spec, 5000, &mut rng);

        let message_len = brakedown_code.message_len;
        let codeword_len = brakedown_code.codeword_len;

        // println!("{:?}\nmessage_len: {}\ncodeword: {}", brakedown_code.spec, message_len, codeword_len);

        let check_times = 100;
        for _ in 0..check_times {
            let k_0 = rng.sample(field_distr);
            let k_1 = rng.sample(field_distr);

            let mut codeword = vec![FF32::ZERO; codeword_len];
            codeword[..message_len]
                .iter_mut()
                .for_each(|x| *x = rng.sample(field_distr));

            let mut codeword_add = vec![FF32::ZERO; codeword_len];
            codeword_add[..message_len]
                .iter_mut()
                .for_each(|x| *x = rng.sample(field_distr));

            let mut codeword_sum: Vec<FF32> = codeword
                .clone()
                .into_iter()
                .zip(codeword_add.clone())
                .map(|(x_0, x_1)| k_0 * x_0 + k_1 * x_1)
                .collect();
            brakedown_code.encode(&mut codeword_sum);

            brakedown_code.encode(&mut codeword);
            brakedown_code.encode(&mut codeword_add);
            let codeword_sum_expected: Vec<FF32> = codeword
                .clone()
                .into_iter()
                .zip(codeword_add.clone())
                .map(|(x_0, x_1)| k_0 * x_0 + k_1 * x_1)
                .collect();

            let num_notequal: usize = codeword_sum_expected
                .iter()
                .zip(codeword_sum.iter())
                .map(|(x_0, x_1)| (x_0 != x_1) as usize)
                .sum();
            assert!(num_notequal == 0);
        }
    }
}
