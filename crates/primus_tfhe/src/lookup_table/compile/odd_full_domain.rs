//! Signed folding of odd plaintext domains into a negacyclic accumulator.

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use super::{fill_negated_tail, upper_midpoint, validate_input_encoding};
use crate::{LookupTableError, rotation::RotationModulusSwitch};

/// Compiles all t messages; the returned domain length is the validated usize t.
/// Upper-half centers carry negated values so negacyclic extraction restores them.
pub(in crate::lookup_table) fn compile<T, LM, M, F>(
    poly_length: PolyLength,
    input_plaintext_modulus: T,
    input_ciphertext_modulus: LM,
    coefficient_modulus: M,
    encoded_output_at: F,
) -> Result<(PolynomialOwned<T>, usize), LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
    F: Fn(usize) -> Result<T, LookupTableError>,
{
    validate_input_encoding(
        poly_length,
        input_plaintext_modulus,
        input_ciphertext_modulus.explicit_value(),
    )?;
    let poly_length = poly_length.get();
    if input_plaintext_modulus & T::ONE == T::ZERO {
        return Err(LookupTableError::EvenPlaintextModulus);
    }
    let input_domain_len: usize = input_plaintext_modulus
        .try_into()
        .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
    if input_domain_len > poly_length {
        return Err(LookupTableError::PlaintextDomainTooLarge {
            domain_len: input_domain_len,
            coefficients_per_output: poly_length,
        });
    }

    let input_codec = RoundedCodec::new(input_plaintext_modulus, input_ciphertext_modulus);
    let modulus_switch = RotationModulusSwitch::new(input_ciphertext_modulus, poly_length * 2, 1);
    // For odd t, multiplying the ideal folded index by 2^{-1} mod t
    // interleaves the lower and upper message halves in increasing order.
    // Odd indices are upper-half inputs and carry a negative stored value.
    let input_at = |folded_index: usize| {
        folded_index / 2
            + if folded_index & 1 == 0 {
                0
            } else {
                input_domain_len / 2 + 1
            }
    };
    let folded_center_at = |input| {
        let encoded = input_codec.encode_value(T::as_from(input), PlaintextEmbedding::Unsigned);
        // Fold the exponent in [0, 2N) into a coefficient index in [0, N).
        modulus_switch.exponent(encoded) & (poly_length - 1)
    };
    let mut polynomial = PolynomialOwned::zero(poly_length);
    let coefficients = polynomial.as_mut();
    let coefficient_modulus_value = coefficient_modulus.explicit_value();
    let mut folded_center = 0;
    let mut coefficient_start = 0;
    for folded_index in 0..input_domain_len {
        let input = input_at(folded_index);
        let (next_input, next_folded_center) = if folded_index + 1 == input_domain_len {
            (0, poly_length) // Negacyclic image of input zero, with value -f(0).
        } else {
            let next_input = input_at(folded_index + 1);
            (next_input, folded_center_at(next_input))
        };
        if folded_center >= next_folded_center {
            return Err(LookupTableError::RotationCenterCollision {
                first_input: input,
                second_input: next_input,
                center_position: next_folded_center,
            });
        }
        let value = encoded_output_at(input)?;
        if coefficient_modulus_value.is_some_and(|q| value >= q) {
            return Err(LookupTableError::EncodedOutputOutOfRange { input });
        }
        let value = if folded_index & 1 == 0 {
            value
        } else {
            coefficient_modulus.reduce_neg(value)
        };
        let coefficient_end = upper_midpoint(folded_center, next_folded_center);
        coefficients[coefficient_start..coefficient_end].fill(value);
        coefficient_start = coefficient_end;
        folded_center = next_folded_center;
    }
    fill_negated_tail(coefficients, coefficient_start, 1, coefficient_modulus);
    Ok((polynomial, input_domain_len))
}
