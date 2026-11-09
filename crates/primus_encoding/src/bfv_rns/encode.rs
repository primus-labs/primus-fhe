use primus_data::{Data, DataMut};
use primus_factor::{FactorMul, FactorSliceOps};
use primus_integer::FheUint;
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;

use super::BfvRnsCodec;
use crate::PlaintextEmbedding;

impl<T, M> BfvRnsCodec<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Validates a complete coefficient-domain plaintext/output boundary.
    fn validate_plaintext(&self, input: &[T], output_len: usize) {
        assert_eq!(
            output_len,
            self.rns_poly_len(input.len()),
            "RNS output length mismatch"
        );
        assert!(
            input.iter().all(|&m| m < self.t),
            "message must be less than plaintext modulus"
        );
    }

    /// Encodes coefficients as `lift(input) * floor(Q/t)` in the ordered CRT basis.
    ///
    /// Centered embedding uses `[-floor(t/2), ceil(t/2))`, including `1 -> -1`
    /// for `t = 2`. Output is overwritten with canonical coefficient-domain
    /// residues, ready for a separate NTT. Each consecutive chunk of `input.len()`
    /// elements corresponds to one modulus in [`Self::base_q`] order.
    /// Message and length validation completes before any writes.
    ///
    /// # Panics
    ///
    /// Panics for messages outside `[0,t)` or an output length other than
    /// `input.len() * moduli_count()`, or if that product overflows `usize`.
    pub fn encode_coeffs_to<A, B>(
        &self,
        input: &Polynomial<A>,
        output: &mut CrtPolynomial<B>,
        embedding: PlaintextEmbedding,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.validate_plaintext(input.as_ref(), output.as_ref().len());
        if input.as_ref().is_empty() {
            return;
        }
        let half = (self.t >> 1u32) + (self.t & T::ONE);
        for ((chunk, &q), &factor) in output
            .as_mut()
            .chunks_exact_mut(input.as_ref().len())
            .zip(self.base_q.moduli_values())
            .zip(self.delta_factor_mod_q.iter())
        {
            match embedding {
                PlaintextEmbedding::Unsigned => {
                    factor.factor_mul_slice_to(input.as_ref(), chunk, q)
                }
                PlaintextEmbedding::Centered => {
                    for (&m, out) in input.as_ref().iter().zip(chunk) {
                        *out = if m < half {
                            factor.factor_mul_modulo(m, q)
                        } else {
                            let value = factor.factor_mul_modulo(self.t - m, q);
                            // A nonzero scaled lift can still be zero in an RNS limb.
                            if value == T::ZERO { value } else { q - value }
                        };
                    }
                }
            }
        }
    }

    /// Adds scaled plaintext coefficients to a coefficient-domain CRT accumulator.
    ///
    /// Uses the same embedding as [`Self::encode_coeffs_to`]. The accumulator
    /// is not cleared; message and length validation completes before any writes.
    ///
    /// # Correctness
    ///
    /// `acc` must use modulus-major coefficient layout in [`Self::base_q`] order.
    /// Each chunk of `input.len()` elements must contain canonical residues
    /// modulo its corresponding `q_i` and remains canonical after addition.
    /// Residue ranges and the basis/domain of the stored data are not checked.
    ///
    /// # Panics
    ///
    /// Panics for messages outside `[0,t)` or an accumulator length other than
    /// `input.len() * moduli_count()`, or if that product overflows `usize`.
    pub fn add_encode_coeffs_assign<A, B>(
        &self,
        input: &Polynomial<A>,
        acc: &mut CrtPolynomial<B>,
        embedding: PlaintextEmbedding,
    ) where
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        self.validate_plaintext(input.as_ref(), acc.as_ref().len());
        if input.as_ref().is_empty() {
            return;
        }
        let half = (self.t >> 1u32) + (self.t & T::ONE);
        for (((chunk, &q), modulus), &factor) in acc
            .as_mut()
            .chunks_exact_mut(input.as_ref().len())
            .zip(self.base_q.moduli_values())
            .zip(self.base_q.moduli())
            .zip(self.delta_factor_mod_q.iter())
        {
            match embedding {
                PlaintextEmbedding::Unsigned => {
                    factor.add_factor_mul_slice_assign(chunk, input.as_ref(), q)
                }
                PlaintextEmbedding::Centered => {
                    for (&m, out) in input.as_ref().iter().zip(chunk) {
                        if m < half {
                            modulus.reduce_add_assign(out, factor.factor_mul_modulo(m, q));
                        } else {
                            modulus.reduce_sub_assign(out, factor.factor_mul_modulo(self.t - m, q));
                        }
                    }
                }
            }
        }
    }
}
