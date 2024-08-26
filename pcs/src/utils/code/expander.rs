use crate::utils::{
    arithmetic::{ceil, entropy, SparseMatrix, SparseMatrixDimension},
    code::{LinearCode, ReedSolomonCode},
};

use algebra::Field;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use super::LinearCodeSpec;

/// BrakedownCode Specification
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExpanderCodeSpec {
    // Code parameter alpha
    alpha: f64,

    // Code parameter beta
    beta: f64,

    // Inversion of ideal code rate
    r: f64,

    // Size of the base field.
    base_field_bits: usize,

    // The threshold to call ReedSoloman Code.
    recursion_threshold: usize,

    // Relative distance of the code
    distance: f64,

    // The ideal code rate = message_len/codeword_len,
    rate: f64,
}

impl ExpanderCodeSpec {
    /// Create an instance of BrakedownCodeSpec
    #[inline]
    pub fn new(
        // lambda: usize,
        alpha: f64,
        beta: f64,
        r: f64,
        base_field_bits: usize,
        recursion_threshold: usize,
    ) -> Self {
        assert!(r != 0.0);
        let rate = 1f64 / r;
        let distance = beta / r;

        // Parameter constraints are taken from Page 18 in [GLSTW21](https://eprint.iacr.org/2021/1043.pdf).
        assert!(0f64 < rate && rate < 1f64);
        assert!(0f64 < distance && distance < 1f64);
        assert!(0f64 < alpha && alpha < 1f64);
        assert!(1.28 * beta < alpha);
        assert!((1f64 - alpha) * r > (1f64 + 2f64 * beta));

        Self {
            alpha,
            beta,
            r,
            base_field_bits,
            recursion_threshold,
            distance,
            rate,
        }
    }

    /// The relative distance of the code
    pub fn distance(&self) -> f64 {
        self.distance
    }

    /// The proximity gap of the code
    pub fn proximity_gap(&self) -> f64 {
        1.0 / 3.0
    }

    /// Return the codeword length of the given message length under this set of code parameters
    ///
    /// # Argument.
    ///
    /// * `message_len` - The length of the message.
    #[inline]
    pub fn codeword_len(&self, message_len: usize) -> usize {
        let (a, b) = self.dimensions(message_len);
        // the systematic part
        message_len +
        // the upper part (the last a.m is consumed by Reedsolomon code)
        a[..a.len()-1].iter().map(|a| a.num_col).sum::<usize>() +
        // the Reedsolomon code length
        b.last().unwrap().num_row +
        // the lower part
        b.iter().map(|b| b.num_col).sum::<usize>()
    }

    // Return the number of nonzere elements in each row of A_n
    #[inline]
    fn c_n(&self, message_len: usize) -> usize {
        let n = message_len as f64;
        let alpha = self.alpha;
        let beta = self.beta;
        std::cmp::min(
            std::cmp::max((1.28 * beta * n).ceil() as usize, ceil(beta * n) + 4),
            ceil(
                ((110.0 / n) + entropy(beta) + alpha * entropy(1.28 * beta / alpha))
                    / (beta * (alpha / (1.28 * beta)).log2()),
            ),
        )
    }

    // Return the num of nonzere elements in each row of B_n
    #[inline]
    fn d_n(&self, message_len: usize) -> usize {
        let log2_q = self.base_field_bits as f64;
        let n = message_len as f64;
        let alpha = self.alpha;
        let beta = self.beta;
        let r = self.r;
        let mu = r - 1f64 - r * alpha; // intermediate value
        let nu = beta + alpha * beta + 0.03; // intermediate value
        std::cmp::min(
            ceil((2.0 * beta + ((r - 1.0) + 110.0 / n) / log2_q) * n),
            ceil(
                (r * alpha * entropy(beta / r) + mu * entropy(nu / mu) + 110.0 / n)
                    / (alpha * beta * (mu / nu).log2()),
            ),
        )
    }

    // At each recursion layer, it needs two matrices A, B
    // We iteratively produce all A, B we need
    //
    // At iteration 1 i.e. the beginning
    // A(n) = M_{n, alpha * n, c_n}
    // B(n) = M_{alpha * r * n, (r - 1 - r * alpha) * n, d_n}
    // with M_{n, m, d} denotes row_num, column_num, nonzero_num, respectively

    // At iteration 2
    // n = alpha * n
    // A(n) = ..., B(n) = ..., proceeding like the above

    // Iteratively produces matrices A, B until n <= n_0
    #[inline]
    fn dimensions(
        &self,
        message_len: usize,
    ) -> (Vec<SparseMatrixDimension>, Vec<SparseMatrixDimension>) {
        let n = message_len;
        let n0 = self.recursion_threshold;
        assert!(n >= n0);

        let a = std::iter::successors(Some(n), |n| Some(ceil(*n as f64 * self.alpha)))
            .tuple_windows()
            .take_while(|(n, _)| n > &n0)
            .map(|(n, m)| SparseMatrixDimension::new(n, m, std::cmp::min(self.c_n(n), m)))
            .collect_vec();

        let b = a
            .iter()
            .map(|a| {
                let n_prime = ceil(a.num_col as f64 * self.r);
                let m_prime = ceil(a.num_row as f64 * self.r) - a.num_row - n_prime;
                SparseMatrixDimension::new(
                    n_prime,
                    m_prime,
                    std::cmp::min(self.d_n(a.num_row), m_prime),
                )
            })
            .collect_vec();

        (a, b)
    }

    // Generate random matrices iteratively
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

impl<F: Field> LinearCodeSpec<F> for ExpanderCodeSpec {
    type Code = ExpanderCode<F>;

    fn code(&self, message_len: usize, rng: &mut (impl Rng + CryptoRng)) -> Self::Code {
        ExpanderCode::<F>::new(self.clone(), message_len, rng)
    }

    fn distance(&self) -> Result<f64, String> {
        Ok(self.distance())
    }

    fn proximity_gap(&self) -> Result<f64, String> {
        Ok(self.proximity_gap())
    }
}

/// Define the struct of linear expander code.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExpanderCode<F> {
    /// Code specification
    pub spec: ExpanderCodeSpec,
    /// The length of the message
    pub message_len: usize,
    /// The length of the codeword.
    pub codeword_len: usize,

    // random matrices which represent expander graphs w.h.p.
    a: Vec<SparseMatrix<F>>,
    // random matrices which represent expander graphs w.h.p.
    b: Vec<SparseMatrix<F>>,
}

impl<F: Field> ExpanderCode<F> {
    /// Create an instance of BrakedownCode
    ///
    /// # Arguments.
    ///
    /// * `spec` - The code specification.
    /// * `message_len` - The length of messages.
    /// * `rng` - The randomness generator.
    #[inline]
    pub fn new(
        spec: ExpanderCodeSpec,
        message_len: usize,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Self {
        assert!(message_len >= spec.recursion_threshold);

        let (a, b) = spec.matrices(message_len, rng);
        let codeword_len = spec.codeword_len(message_len);

        Self {
            spec,
            message_len,
            codeword_len,
            a,
            b,
        }
    }
}

impl<F: Field> LinearCode<F> for ExpanderCode<F> {
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

    /// Encode iteratively.
    ///
    /// Enc(x_0) = x_0 | x_1 | ... | x_{k-1} | x_k | x_{k+1} | ... | x_l
    /// where
    /// \forall 0 <= i < k-1, x_{i+1} = x_i * A_i
    /// \forall 0 <= i < l-k-1, x_{k+i+1} = ( x_{k-i} |...| x_{k+i} ) * B_{l-k-i}
    /// x_k = ReedSolomanCode

    fn encode(&self, target: &mut [F]) {
        assert_eq!(target.len(), self.codeword_len);
        target[self.message_len..].fill(F::zero());

        // Compute x1 = x*A | x2 = x*A^2| x3 = x*A^3| ... | x_{k-1} = x*A^{k-1}
        let mut input_offset = 0;
        self.a[..self.a.len() - 1].iter().for_each(|a| {
            let (input, output) = target[input_offset..].split_at_mut(a.dimension.num_row);
            a.add_multiplied_vector(input, &mut output[..a.dimension.num_col]);
            input_offset += a.dimension.num_row;
        });

        // Compute x_k = ReedSoloman(x*A^k)
        let a_last = self.a.last().unwrap();
        let b_last = self.b.last().unwrap();

        let (input, output) = target[input_offset..].split_at_mut(a_last.dimension.num_row);
        a_last.add_multiplied_vector(input, &mut output[..a_last.dimension.num_col]);

        let reedsolomon_code =
            ReedSolomonCode::new(a_last.dimension.num_col, b_last.dimension.num_row);
        reedsolomon_code.encode(&mut output[..b_last.dimension.num_row]);

        let mut output_offset = input_offset + a_last.dimension.num_row + b_last.dimension.num_row;
        input_offset += a_last.dimension.num_row + a_last.dimension.num_col;

        // Compute x_{k+1} = x_k*B | x_{k+2} = (x_{k-1}|x_k|x_{k+1})*B | x_{k+3} =  (x_{k-2}|x_{k-1}|x_k|x_{k+1}|x_{k+2})*B | ...
        self.a
            .iter()
            .rev()
            .zip(self.b.iter().rev())
            .for_each(|(a, b)| {
                input_offset -= a.dimension.num_col;
                let (input, output) = target.split_at_mut(output_offset);
                b.add_multiplied_vector(
                    &input[input_offset..input_offset + b.dimension.num_row],
                    &mut output[..b.dimension.num_col],
                );
                output_offset += b.dimension.num_col;
            });

        assert_eq!(input_offset, self.a[0].dimension.num_row);
        assert_eq!(output_offset, target.len());
    }

    fn encode_ext<EF>(&self, target: &mut [EF])
    where
        F: Field,
        EF: algebra::AbstractExtensionField<F>,
    {
        assert_eq!(target.len(), self.codeword_len);
        target[self.message_len..].fill(EF::zero());

        // Compute x1 = x*A | x2 = x*A^2| x3 = x*A^3| ... | x_{k-1} = x*A^{k-1}
        let mut input_offset = 0;
        self.a[..self.a.len() - 1].iter().for_each(|a| {
            let (input, output) = target[input_offset..].split_at_mut(a.dimension.num_row);
            a.add_multiplied_vector_ext(input, &mut output[..a.dimension.num_col]);
            input_offset += a.dimension.num_row;
        });

        // Compute x_k = ReedSoloman(x*A^k)
        let a_last = self.a.last().unwrap();
        let b_last = self.b.last().unwrap();

        let (input, output) = target[input_offset..].split_at_mut(a_last.dimension.num_row);
        a_last.add_multiplied_vector_ext(input, &mut output[..a_last.dimension.num_col]);

        let reedsolomon_code =
            ReedSolomonCode::new(a_last.dimension.num_col, b_last.dimension.num_row);
        reedsolomon_code.encode(&mut output[..b_last.dimension.num_row]);

        let mut output_offset = input_offset + a_last.dimension.num_row + b_last.dimension.num_row;
        input_offset += a_last.dimension.num_row + a_last.dimension.num_col;

        // Compute x_{k+1} = x_k*B | x_{k+2} = (x_{k-1}|x_k|x_{k+1})*B | x_{k+3} =  (x_{k-2}|x_{k-1}|x_k|x_{k+1}|x_{k+2})*B | ...
        self.a
            .iter()
            .rev()
            .zip(self.b.iter().rev())
            .for_each(|(a, b)| {
                input_offset -= a.dimension.num_col;
                let (input, output) = target.split_at_mut(output_offset);
                b.add_multiplied_vector_ext(
                    &input[input_offset..input_offset + b.dimension.num_row],
                    &mut output[..b.dimension.num_col],
                );
                output_offset += b.dimension.num_col;
            });

        assert_eq!(input_offset, self.a[0].dimension.num_row);
        assert_eq!(output_offset, target.len());
    }
}
