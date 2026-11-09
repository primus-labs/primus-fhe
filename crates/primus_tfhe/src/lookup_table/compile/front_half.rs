//! Compilation geometry for the current unsigned front-half input domain.
//!
//! Let `N` be the polynomial length, `s` the padded output count and `D` the
//! programmed input prefix length. Each output has `M = N / s` coefficients.
//! An output group holds `s` coefficients: all outputs for one input, then padding.
//! Repeating this group fills that input's interval; interval lengths may differ.
//! For message `m`, first encode `E(m) = round(m * q_in / t) mod q_in`, then
//! compute `c[m] = R(E(m), q_in, 2M)` using the rounding rule in
//! [`crate::rotation`]. Both rounds have upward ties for unsigned input.
//! Combining the two rounds can move plateau boundaries.
//!
//! Centers use per-output coefficient coordinates. Append the terminating center
//! `c[D] = min(R(E(D), q_in, 2M), M)` with value `-f(0)`. Each position in
//! `0..M` receives the nearest center's value, with ties going to the higher
//! center. All centers, including the terminating one, must be strictly
//! increasing. This defines both the last plateau and the unprogrammed tail; the
//! latter is not an additional valid input domain. Negative rotation positions
//! use the ring's negacyclic extension.
//!
//! Output `j` occupies coefficients `s*r + j`. Extracting coefficient `j` after
//! multiplying by `X^(-s*r)` reads that output at position `r`, negating
//! once for each crossing of `M`. For `k` outputs, `s = next_power_of_two(k)`;
//! slots `k..s` are zero and only `0..k` are extracted.

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_shape::PolyLength;

use super::{fill_negated_tail, repeat_output_group, upper_midpoint, validate_input_encoding};

use crate::{LookupTableError, rotation::RotationModulusSwitch};

/// Returns the front-half message count `ceil(t/2)`, checking that t fits usize.
/// LUT compilers separately validate the actual programmed prefix's capacity
/// and rotation centers; the complete message domain need not fit one polynomial.
#[doc(hidden)]
pub fn front_half_domain_len<T: FheUint>(plaintext_modulus: T) -> Result<usize, LookupTableError> {
    let plaintext_domain_len: usize = plaintext_modulus
        .try_into()
        .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
    Ok(plaintext_domain_len.div_ceil(2))
}

/// Compiles a front-half prefix directly into the final interleaved polynomial.
/// Each nonempty input interval receives one output group, then repeats it
/// through the remaining positions. No per-output storage is needed.
pub(in crate::lookup_table) fn compile<T, LM, M, F>(
    input_domain_len: usize,
    poly_length: PolyLength,
    output_count: usize,
    input_plaintext_modulus: T,
    input_ciphertext_modulus: LM,
    coefficient_modulus: M,
    encoded_output_at: F,
) -> Result<PolynomialOwned<T>, LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    validate(
        input_domain_len,
        poly_length,
        output_count,
        input_plaintext_modulus,
        input_ciphertext_modulus.explicit_value(),
    )?;
    let mut polynomial = PolynomialOwned::zero(poly_length.get());
    compile_to(
        input_domain_len,
        output_count,
        input_plaintext_modulus,
        input_ciphertext_modulus,
        coefficient_modulus,
        encoded_output_at,
        polynomial.as_mut(),
    )?;
    Ok(polynomial)
}

/// Checks encoding and capacity before allocating one polynomial or a batch.
pub(in crate::lookup_table) fn validate<T: FheUint>(
    input_domain_len: usize,
    poly_length: PolyLength,
    output_count: usize,
    input_plaintext_modulus: T,
    input_ciphertext_modulus: Option<T>,
) -> Result<(), LookupTableError> {
    validate_input_encoding(
        poly_length,
        input_plaintext_modulus,
        input_ciphertext_modulus,
    )?;
    let max_domain_len = front_half_domain_len(input_plaintext_modulus)?;
    let poly_length = poly_length.get();
    if input_domain_len == 0 || input_domain_len > max_domain_len {
        return Err(LookupTableError::InvalidInputDomain {
            domain_len: input_domain_len,
            max_domain_len,
        });
    }
    if output_count == 0 {
        return Err(LookupTableError::EmptyOutputs);
    }
    if output_count > poly_length {
        return Err(LookupTableError::OutputCountTooLarge {
            output_count,
            poly_length,
        });
    }

    let padded_output_count = output_count.next_power_of_two();
    let coefficients_per_output = poly_length / padded_output_count;
    if input_domain_len > coefficients_per_output {
        return Err(LookupTableError::PlaintextDomainTooLarge {
            domain_len: input_domain_len,
            coefficients_per_output,
        });
    }
    Ok(())
}

/// Fills a polynomial whose encoding and shape have passed `validate`.
/// Overwrites every coefficient on success; a center collision or invalid
/// callback value may leave a partially written output.
pub(in crate::lookup_table) fn compile_to<T, LM, M, F>(
    input_domain_len: usize,
    output_count: usize,
    input_plaintext_modulus: T,
    input_ciphertext_modulus: LM,
    coefficient_modulus: M,
    encoded_output_at: F,
    coefficients: &mut [T],
) -> Result<(), LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    let padded_output_count = output_count.next_power_of_two();
    let coefficients_per_output = coefficients.len() / padded_output_count;

    let input_codec = RoundedCodec::new(input_plaintext_modulus, input_ciphertext_modulus);
    let center_modulus_switch =
        RotationModulusSwitch::new(input_ciphertext_modulus, coefficients_per_output * 2, 1);
    let center_position_at = |input| {
        // The validated front-half domain guarantees input <= D < t, so it fits T.
        let encoded = input_codec.encode_value(T::as_from(input), PlaintextEmbedding::Unsigned);
        center_modulus_switch.exponent(encoded)
    };
    let coefficient_modulus_value = coefficient_modulus.explicit_value();

    // Centers use per-output coordinates; slice boundaries index the polynomial.
    let mut center_position = 0;
    let mut coefficient_start = 0;
    for input in 0..input_domain_len {
        let mut next_center_position = center_position_at(input + 1);
        // For odd t, clamp the terminal center to input zero's negacyclic image
        // at coefficients_per_output; short prefixes keep their tail.
        if input + 1 == input_domain_len {
            next_center_position = next_center_position.min(coefficients_per_output);
        }
        if center_position >= next_center_position {
            return Err(LookupTableError::RotationCenterCollision {
                first_input: input,
                second_input: input + 1,
                center_position: next_center_position,
            });
        }
        let coefficient_end =
            upper_midpoint(center_position, next_center_position) * padded_output_count;
        fill_input_interval(
            &mut coefficients[coefficient_start..coefficient_end],
            input,
            output_count,
            padded_output_count,
            coefficient_modulus_value,
            &encoded_output_at,
        )?;
        coefficient_start = coefficient_end;
        center_position = next_center_position;
    }
    fill_negated_tail(
        coefficients,
        coefficient_start,
        padded_output_count,
        coefficient_modulus,
    );
    Ok(())
}

/// Evaluates one output group and repeats it through a nonempty input interval.
/// `0 < output_count <= padded_output_count`; the interval length is a multiple
/// of `padded_output_count`.
fn fill_input_interval<T, F>(
    input_interval: &mut [T],
    input: usize,
    output_count: usize,
    padded_output_count: usize,
    coefficient_modulus_value: Option<T>,
    encoded_output_at: &F,
) -> Result<(), LookupTableError>
where
    T: FheUint,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    for (output_index, slot) in input_interval[..output_count].iter_mut().enumerate() {
        let value = encoded_output_at(input, output_index)?;
        if coefficient_modulus_value.is_some_and(|q| value >= q) {
            return Err(LookupTableError::EncodedOutputOutOfRange { input });
        }
        *slot = value;
    }
    input_interval[output_count..padded_output_count].fill(T::ZERO);
    repeat_output_group(input_interval, padded_output_count);
    Ok(())
}
