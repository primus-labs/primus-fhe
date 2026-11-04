//! u64 coefficient-domain basis operations for HPS-family BFV multiplication.

use primus_factor::{FactorMul, ShoupFactor};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_reduce::{Reduce, ReduceDotProduct, ReduceInv, ReduceMul, ReduceNeg, ReduceSub};

use crate::{BaseConverter, RNSBase, Residues, RnsError};

type Base = RNSBase<u64, BarrettModulus<u64>>;

/// Prepared HPS operations between disjoint odd u64 bases Q and P.
///
/// All arrays use coefficient-domain, modulus-major storage. This object owns
/// only immutable precomputation; [`Self::workspace`] prepares all online
/// storage. The operations do not impose a size relation between P and Q.
/// In particular the P/Q map has the bounded residual documented on
/// [`Self::scale_q_to_p`], rather than the exact multiplication requirement P>NQ.
/// A BFV caller must establish its own noise and auxiliary-basis conditions.
pub struct HpsRns {
    q_to_p: CenteredConversion,
    p_to_q: CenteredConversion,
    negative_p_q_hat_inverse: Vec<ShoupFactor<u64>>,
    q_inverse_mod_p: Vec<u64>,
    p_inverse_mod_q: Vec<ShoupFactor<u64>>,
    t_mod_q: Vec<ShoupFactor<u64>>,
    t_mod_p: Vec<ShoupFactor<u64>>,
}

/// Reusable storage for one HPS batch size.
///
/// Construct with [`HpsRns::workspace`]. The workspace contains coefficient
/// buffers and the exact-integer fallback storage used at CRT half boundaries;
/// none of the online operations allocate.
pub struct HpsRnsWorkspace {
    value_count: usize,
    max_moduli: usize,
    conversion: ConversionWorkspace,
    scaled_p: Vec<u64>,
}

struct ConversionWorkspace {
    adjusted: Vec<u64>,
    corrections: Vec<u64>,
    residues: Vec<u64>,
    value: Vec<u64>,
}

struct CenteredConversion {
    converter: BaseConverter<u64, BarrettModulus<u64>>,
    product_mod_output: Vec<u64>,
    half_product: Vec<u64>,
    inverse_moduli: Vec<f64>,
    quotient_error: f64,
}

impl HpsRns {
    /// Prepares disjoint, pairwise-coprime odd bases below 2^62 and scale t>0.
    ///
    /// The basis handles share their existing CRT precomputation. Neither this
    /// constructor nor these numerical operations certify BFV parameters.
    ///
    /// # Errors
    /// Returns an error for an even/out-of-range modulus, zero scale or bases
    /// that are not coprime to one another.
    ///
    /// # Panics
    /// Panics if complete precomputation lengths overflow `usize`.
    pub fn try_new(base_q: &Base, base_p: &Base, t: u64) -> Result<Self, RnsError> {
        for &modulus in base_q.moduli_values().iter().chain(base_p.moduli_values()) {
            if !(3..(1 << 62)).contains(&modulus) || modulus & 1 == 0 {
                return Err(RnsError::UnsupportedHpsModulus { modulus });
            }
        }
        if t == 0 {
            return Err(RnsError::ZeroScale);
        }
        for &q in base_q.moduli_values() {
            for &p in base_p.moduli_values() {
                if gcd(q, p) != 1 {
                    return Err(RnsError::NonCoprimeModuli);
                }
            }
        }
        let negative_p_q_hat_inverse = base_q
            .moduli()
            .iter()
            .zip(base_q.inv_punctured_product_mod_modulus())
            .map(|(q, inverse)| {
                let negative_p = q.reduce_neg(q.reduce(base_p.moduli_product().digits()));
                ShoupFactor::new(inverse.factor_mul_modulo(negative_p, q.value()), q.value())
            })
            .collect();
        let mut q_inverse_mod_p = Vec::with_capacity(
            base_q
                .moduli_count()
                .checked_mul(base_p.moduli_count())
                .expect("HPS matrix length overflow"),
        );
        for p in base_p.moduli() {
            for &q in base_q.moduli_values() {
                q_inverse_mod_p.push(p.reduce_inv(p.reduce(q)));
            }
        }
        let p_inverse_mod_q = base_q
            .moduli()
            .iter()
            .map(|q| {
                ShoupFactor::new(
                    q.reduce_inv(q.reduce(base_p.moduli_product().digits())),
                    q.value(),
                )
            })
            .collect();
        let t_mod_q = scale_factors(base_q, t);
        let t_mod_p = scale_factors(base_p, t);
        Ok(Self {
            q_to_p: CenteredConversion::new(base_q, base_p),
            p_to_q: CenteredConversion::new(base_p, base_q),
            negative_p_q_hat_inverse,
            q_inverse_mod_p,
            p_inverse_mod_q,
            t_mod_q,
            t_mod_p,
        })
    }

    /// Allocates reusable online scratch for exactly `value_count` values.
    ///
    /// # Panics
    /// Panics if a complete array length overflows `usize`.
    #[must_use]
    pub fn workspace(&self, value_count: usize) -> HpsRnsWorkspace {
        let max_moduli = self.q().moduli_count().max(self.p().moduli_count());
        HpsRnsWorkspace {
            value_count,
            max_moduli,
            conversion: ConversionWorkspace {
                adjusted: vec![
                    0;
                    max_moduli
                        .checked_mul(value_count)
                        .expect("HPS workspace length overflow")
                ],
                corrections: vec![0; value_count],
                residues: vec![0; max_moduli],
                value: vec![0; max_moduli],
            },
            scaled_p: vec![
                0;
                self.p()
                    .moduli_count()
                    .checked_mul(value_count)
                    .expect("HPS workspace length overflow")
            ],
        }
    }

    /// Converts the exact centered Q representative to P.
    ///
    /// Each input coefficient x is interpreted in `[-(Q-1)/2,(Q-1)/2]`.
    /// All input residues must be canonical. `input` and `output` have Q-count
    /// and P-count chunks respectively, each of length `value_count`.
    /// Floating point selects the CRT correction only when a conservative
    /// error interval proves it unambiguous; half boundaries use exact CRT.
    ///
    /// # Panics
    /// Rejects incorrect complete lengths or workspace shape before any writes.
    pub fn expand_q_to_p(
        &self,
        input: &[u64],
        output: &mut [u64],
        value_count: usize,
        workspace: &mut HpsRnsWorkspace,
    ) {
        self.validate(input.len(), output.len(), value_count, workspace, true);
        self.q_to_p
            .expand(input, output, value_count, &mut workspace.conversion);
    }

    /// Converts the exact centered P representative to Q.
    ///
    /// Inherits [`Self::expand_q_to_p`]'s canonical input, layout, exactness and
    /// prewrite checks, with P and Q exchanged.
    pub fn expand_p_to_q(
        &self,
        input: &[u64],
        output: &mut [u64],
        value_count: usize,
        workspace: &mut HpsRnsWorkspace,
    ) {
        self.validate(input.len(), output.len(), value_count, workspace, false);
        self.p_to_q
            .expand(input, output, value_count, &mut workspace.conversion);
    }

    /// Maps Q coefficients to P with the HPS P/Q prescaling rule.
    ///
    /// For each canonical input residue x_i, forms
    /// `d_i = [-P*x_i*(Q/q_i)^(-1)] mod q_i` and returns
    /// `sum_i d_i*q_i^(-1) mod p_j` for every output modulus p_j.
    /// For any integer Q representative x this is the P residue of the integer
    /// `P*x/Q + epsilon`, where `epsilon=sum_i d_i/q_i` lies in `[0,#Q)`.
    /// This is a bounded one-sided residual, **not** nearest rounding or an
    /// exact lift of x. Centering its output can introduce a multiple of P;
    /// the consuming multiplication must account for that term.
    ///
    /// # Panics
    /// Inherits [`Self::expand_q_to_p`]'s complete prewrite shape checks.
    pub fn scale_q_to_p(
        &self,
        input: &[u64],
        output: &mut [u64],
        value_count: usize,
        workspace: &mut HpsRnsWorkspace,
    ) {
        self.validate(input.len(), output.len(), value_count, workspace, true);
        if value_count == 0 {
            return;
        }
        let count_q = self.q().moduli_count();
        let adjusted = &mut workspace.conversion.adjusted[..input.len()];
        for (i, ((chunk, factor), &q)) in input
            .chunks_exact(value_count)
            .zip(&self.negative_p_q_hat_inverse)
            .zip(self.q().moduli_values())
            .enumerate()
        {
            for (coefficient, &value) in chunk.iter().enumerate() {
                adjusted[coefficient * count_q + i] = factor.factor_mul_modulo(value, q);
            }
        }
        for ((chunk, matrix), p) in output
            .chunks_exact_mut(value_count)
            .zip(self.q_inverse_mod_p.chunks_exact(count_q))
            .zip(self.p().moduli())
        {
            for (out, residues) in chunk.iter_mut().zip(adjusted.chunks_exact(count_q)) {
                *out = p.reduce_dot_product(residues, matrix);
            }
        }
    }

    /// Computes exact `nearest(t*z/P) mod Q` from the Q and P residues of z.
    ///
    /// The output is independent of which QP integer representative is chosen.
    /// Computes `r=center_P(t*z)` then `(t*z-r)/P` in Q. Because P is odd,
    /// the integer numerator never produces a half-integer tie. Inputs must be
    /// canonical and use the same integer z; all three arrays are
    /// modulus-major, with Q/P/Q chunks of `value_count` coefficients.
    ///
    /// # Panics
    /// Rejects all complete input/output/workspace shapes before any writes.
    pub fn scale_and_round(
        &self,
        input_q: &[u64],
        input_p: &[u64],
        output_q: &mut [u64],
        value_count: usize,
        workspace: &mut HpsRnsWorkspace,
    ) {
        self.validate(input_p.len(), output_q.len(), value_count, workspace, false);
        assert_eq!(input_q.len(), output_q.len());
        if value_count == 0 {
            return;
        }
        let scaled_p = &mut workspace.scaled_p;
        for (((input, output), factor), &p) in input_p
            .chunks_exact(value_count)
            .zip(scaled_p.chunks_exact_mut(value_count))
            .zip(&self.t_mod_p)
            .zip(self.p().moduli_values())
        {
            for (out, &value) in output.iter_mut().zip(input) {
                *out = factor.factor_mul_modulo(value, p);
            }
        }
        self.p_to_q
            .expand(scaled_p, output_q, value_count, &mut workspace.conversion);
        for ((((input, output), t), inverse_p), q) in input_q
            .chunks_exact(value_count)
            .zip(output_q.chunks_exact_mut(value_count))
            .zip(&self.t_mod_q)
            .zip(&self.p_inverse_mod_q)
            .zip(self.q().moduli())
        {
            for (out, &value) in output.iter_mut().zip(input) {
                *out = inverse_p.factor_mul_modulo(
                    q.reduce_sub(t.factor_mul_modulo(value, q.value()), *out),
                    q.value(),
                );
            }
        }
    }

    /// Borrows the ordered computation-only P basis.
    #[must_use]
    pub fn base_p(&self) -> &Base {
        self.p()
    }

    fn q(&self) -> &Base {
        &self.q_to_p.converter.input_base
    }
    fn p(&self) -> &Base {
        &self.q_to_p.converter.output_base
    }

    fn validate(
        &self,
        input_len: usize,
        output_len: usize,
        n: usize,
        workspace: &HpsRnsWorkspace,
        q_to_p: bool,
    ) {
        let (input_count, output_count) = if q_to_p {
            (self.q().moduli_count(), self.p().moduli_count())
        } else {
            (self.p().moduli_count(), self.q().moduli_count())
        };
        assert_eq!(
            input_len,
            input_count
                .checked_mul(n)
                .expect("HPS input length overflow")
        );
        assert_eq!(
            output_len,
            output_count
                .checked_mul(n)
                .expect("HPS output length overflow")
        );
        assert_eq!(
            workspace.value_count, n,
            "HPS workspace value count mismatch"
        );
        assert!(
            workspace.max_moduli >= input_count.max(output_count),
            "HPS workspace basis count mismatch"
        );
        assert_eq!(
            workspace.scaled_p.len(),
            self.p().moduli_count() * n,
            "HPS workspace P shape mismatch"
        );
    }
}

impl CenteredConversion {
    fn new(input: &Base, output: &Base) -> Self {
        let product = input.moduli_product();
        let words = product.digits();
        let half_product = words
            .iter()
            .enumerate()
            .map(|(i, &word)| (word >> 1) | (words.get(i + 1).copied().unwrap_or(0) << 63))
            .collect();
        let count = input.moduli_count() as f64;
        Self {
            converter: BaseConverter::new(input, output),
            product_mod_output: output.moduli().iter().map(|p| p.reduce(words)).collect(),
            half_product,
            inverse_moduli: input
                .moduli_values()
                .iter()
                .map(|&q| 1.0 / q as f64)
                .collect(),
            // With u=2^-53 the cast/reciprocal/multiply chain contributes <5u
            // absolute error per term in [0,1]. Sequential addition contributes
            // <2u*k^2 for k*u<1/4. This deliberately larger bound also covers
            // the rounding in sum+0.5 and the boundary-distance comparison.
            // For larger k it exceeds 1/2, so every value takes exact fallback.
            quotient_error: (count + 2.0) * (count + 2.0) * 2.0_f64.powi(-48),
        }
    }

    fn expand(
        &self,
        input: &[u64],
        output: &mut [u64],
        n: usize,
        workspace: &mut ConversionWorkspace,
    ) {
        if n == 0 {
            return;
        }
        let source = &self.converter.input_base;
        let destination = &self.converter.output_base;
        let count = source.moduli_count();
        if count == 1 {
            let q = source.moduli_values()[0];
            for ((chunk, p), &q_mod_p) in output
                .chunks_exact_mut(n)
                .zip(destination.moduli())
                .zip(&self.product_mod_output)
            {
                for (out, &value) in chunk.iter_mut().zip(input) {
                    let value_p = p.reduce(value);
                    *out = if value > q / 2 {
                        p.reduce_sub(value_p, q_mod_p)
                    } else {
                        value_p
                    };
                }
            }
            return;
        }
        let adjusted = &mut workspace.adjusted[..input.len()];
        self.converter
            .fast_convert_array(input, output, n, adjusted);
        for (correction, residues) in workspace
            .corrections
            .iter_mut()
            .zip(adjusted.chunks_exact(count))
        {
            let sum = residues
                .iter()
                .zip(&self.inverse_moduli)
                .map(|(&x, &inverse)| x as f64 * inverse)
                .sum::<f64>();
            let nearest = (sum + 0.5).floor();
            *correction = if (sum - nearest).abs() + self.quotient_error < 0.5 {
                nearest as u64
            } else {
                u64::MAX
            };
        }
        for ((chunk, p), &product) in output
            .chunks_exact_mut(n)
            .zip(destination.moduli())
            .zip(&self.product_mod_output)
        {
            for (out, &correction) in chunk.iter_mut().zip(&workspace.corrections) {
                if correction != u64::MAX {
                    *out = p.reduce_sub(*out, p.reduce_mul(p.reduce(correction), product));
                }
            }
        }
        for (index, &correction) in workspace.corrections.iter().enumerate() {
            if correction != u64::MAX {
                continue;
            }
            let residues = &mut workspace.residues[..count];
            for (residue, chunk) in residues.iter_mut().zip(input.chunks_exact(n)) {
                *residue = chunk[index];
            }
            let value = &mut workspace.value[..source.big_uint_value_len()];
            source.compose_to(Residues(residues), BigUint(value));
            let negative = value
                .iter()
                .rev()
                .cmp(self.half_product.iter().rev())
                .is_gt();
            for ((chunk, p), &product) in output
                .chunks_exact_mut(n)
                .zip(destination.moduli())
                .zip(&self.product_mod_output)
            {
                let reduced = p.reduce(&*value);
                chunk[index] = if negative {
                    p.reduce_sub(reduced, product)
                } else {
                    reduced
                };
            }
        }
    }
}

fn scale_factors(base: &Base, t: u64) -> Vec<ShoupFactor<u64>> {
    base.moduli()
        .iter()
        .map(|q| ShoupFactor::new(q.reduce(t), q.value()))
        .collect()
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
