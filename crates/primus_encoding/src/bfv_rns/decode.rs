use primus_data::DataMut;
use primus_factor::FactorMul;
use primus_integer::{BigUint, FheUint, multiply_many_values};
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::FieldContext;

use super::{BfvRnsCodec, BfvRnsCodecError};
use crate::PlaintextEmbedding;

impl<T, M> BfvRnsCodec<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Checks a sufficient recovery bound for all messages with the given embedding.
    ///
    /// For phase `c = floor(Q/t)*m + e (mod Q)`, let `E` be
    /// `maximum_noise_magnitude`, `r = Q % t` and `k = moduli_count()`.
    /// This checks `(t*E + r*A)/Q + k/gamma < 1/2`, where `A = t-1`
    /// for unsigned lifting and `A = floor(t/2)` for centered lifting.
    /// Uses exact integer arithmetic and rejects equality at the boundary.
    ///
    /// The bound is conservative: failure does not prove a particular ciphertext
    /// will fail to decrypt. The caller supplies a bound on the complete phase
    /// noise, including any public-key or homomorphic-operation contributions.
    /// This does not inspect a ciphertext or establish a security level.
    ///
    /// # Errors
    ///
    /// Returns [`BfvRnsCodecError::InsufficientNoiseRecovery`] when the sufficient
    /// bound is not strictly satisfied.
    pub fn validate_noise_bound(
        &self,
        maximum_noise_magnitude: T,
        embedding: PlaintextEmbedding,
    ) -> Result<(), BfvRnsCodecError<T>> {
        let modulus_product = self.base_q.moduli_product();
        let remainder = self.t_modulus.reduce(modulus_product.digits());
        let maximum_lift_magnitude = match embedding {
            PlaintextEmbedding::Unsigned => self.t - T::ONE,
            PlaintextEmbedding::Centered => self.t >> 1u32,
        };
        // Constructor validation ensures 4*k fits in T and gamma > 4*k.
        let moduli_count = T::try_from(self.moduli_count())
            .expect("validated RNS modulus count fits in the coefficient type");

        // Cross-multiply the bound: 2*gamma*(t*E + r*A) < (gamma-2*k)*Q.
        // All products stay multi-limb, including when E occupies the full word.
        let mut scaled_noise =
            multiply_many_values(&[T::TWO, self.gamma, self.t, maximum_noise_magnitude]);
        let mut scaled_drift =
            multiply_many_values(&[T::TWO, self.gamma, remainder, maximum_lift_magnitude]);
        let mut recovery_capacity = BigUint(modulus_product.digits().to_vec());
        let carry = recovery_capacity.mul_value_assign(self.gamma - T::TWO * moduli_count);
        recovery_capacity.0.push(carry);

        // BigUint addition/comparison requires matching widths. One extra limb
        // holds the sum even if both scaled terms fill their individual widths.
        let limb_count = scaled_noise
            .len()
            .max(scaled_drift.len())
            .max(recovery_capacity.len())
            + 1;
        scaled_noise.0.resize(limb_count, T::ZERO);
        scaled_drift.0.resize(limb_count, T::ZERO);
        recovery_capacity.0.resize(limb_count, T::ZERO);
        let carry = scaled_noise.add_assign(&scaled_drift);
        debug_assert!(!carry);
        if scaled_noise.cmp(&recovery_capacity).is_lt() {
            Ok(())
        } else {
            Err(BfvRnsCodecError::InsufficientNoiseRecovery {
                maximum_noise_magnitude,
                embedding,
            })
        }
    }

    /// Exact scratch length for decoding `poly_length` coefficients.
    /// Returns zero for a single-modulus basis, otherwise
    /// `poly_length * moduli_count()` elements.
    ///
    /// # Panics
    ///
    /// Panics if the required scratch length overflows `usize`.
    #[must_use]
    pub fn decode_scratch_len(&self, poly_length: usize) -> usize {
        self.converter_q_to_t_gamma
            .fast_convert_array_scratch_len(poly_length)
    }

    /// Decodes coefficient-domain CRT residues into canonical coefficients in `[0,t)`.
    ///
    /// `msg_mod_q` is overwritten as workspace; `msg` receives the decoded
    /// coefficients. `fast_convert_buffer` must contain exactly
    /// `decode_scratch_len(msg.len())` elements and need not be zeroed.
    ///
    /// # Correctness
    ///
    /// `msg_mod_q` must use modulus-major coefficient layout in [`Self::base_q`]
    /// order: each chunk of `msg.len()` elements contains canonical residues
    /// modulo its corresponding `q_i`. Residue ranges and basis/domain are not
    /// checked; NTT data must be inverse-transformed before this call.
    ///
    /// Base conversion inherits [`primus_rns::BaseConverter::fast_convert`]'s
    /// cross-modulus dot-product contract. The Barrett contexts used here already
    /// guarantee its operand bounds, even when a source residue exceeds `t` or
    /// `gamma`. A single-modulus basis uses direct reduction.
    ///
    /// For phase `c = delta*m + e (mod Q)`, where `delta = floor(Q/t)` and `m`
    /// is the chosen integer lift, a sufficient recovery condition is
    /// `abs(t*e - (Q % t)*m)/Q + k/gamma < 1/2`, with `k = moduli_count()`.
    /// This includes encoding drift and the fast base-conversion error.
    ///
    /// # Panics
    ///
    /// Panics if `msg_mod_q.len()` differs from `msg.len() * moduli_count()`,
    /// that product overflows `usize`, or `fast_convert_buffer.len()` differs
    /// from `decode_scratch_len(msg.len())`. Lengths are checked before any writes.
    pub fn decode_coeffs_to<A, B>(
        &self,
        msg_mod_q: &mut CrtPolynomial<A>,
        msg: &mut Polynomial<B>,
        fast_convert_buffer: &mut [T],
    ) where
        A: DataMut<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = msg.as_ref().len();
        let rns_poly_len = self.rns_poly_len(poly_length);
        assert_eq!(
            msg_mod_q.as_ref().len(),
            rns_poly_len,
            "RNS input length mismatch"
        );
        assert_eq!(
            fast_convert_buffer.len(),
            self.decode_scratch_len(poly_length),
            "RNS scratch length mismatch"
        );
        if poly_length == 0 {
            return;
        }

        let t = self.t;
        let gamma = self.gamma;
        let t_modulus = self.t_modulus;
        let decode_factor_mod_t = self.decode_factor_mod_t_gamma[0];
        let decode_factor_mod_gamma = self.decode_factor_mod_t_gamma[1];
        let inv_gamma_mod_t = self.inv_gamma_mod_t;
        let msg = msg.as_mut();

        // Let x = t*gamma*c mod Q. Fast conversion yields x + alpha*Q,
        // 0 <= alpha < k. Multiplying by -Q^-1 gives
        // z = floor(t*gamma*c/Q) - alpha modulo t and gamma.
        // Subtract centered(z mod gamma) in Z_t, then divide by gamma.
        msg_mod_q.mul_factor_assign(
            self.t_gamma_factor_mod_q.as_ref(),
            poly_length,
            self.base_q.moduli_values(),
        );

        self.converter_q_to_t_gamma
            .fast_convert_array_to_pair_iter(msg_mod_q.as_ref(), poly_length, fast_convert_buffer)
            .zip(msg.iter_mut())
            .for_each(|((y_t, y_gamma), m)| {
                // Distribute γ^-1 over both terms so the converted coefficient
                // can be finalized here, without a second output pass. Shoup
                // accepts the full-width correction; reducing it to t first
                // is unnecessary.
                let y_t = decode_factor_mod_t.factor_mul_modulo(y_t, t);
                let y_gamma = decode_factor_mod_gamma.factor_mul_modulo(y_gamma, gamma);

                *m = if y_gamma > (gamma >> 1u32) {
                    t_modulus.reduce_add(y_t, inv_gamma_mod_t.factor_mul_modulo(gamma - y_gamma, t))
                } else {
                    t_modulus.reduce_sub(y_t, inv_gamma_mod_t.factor_mul_modulo(y_gamma, t))
                };
            });
    }
}
