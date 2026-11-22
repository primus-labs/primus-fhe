//! Single-modulus contracts checked with independent `u128` arithmetic.

use primus_encoding::{MessageDecoder, PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::{PrepareModulusSwitch, ReduceAdd};

fn round_half_up(numerator: u128, denominator: u128) -> u128 {
    (numerator + denominator / 2) / denominator
}

// Keep signed magnitude separate: casting a centered negative value to u128
// before scaling would change the rounding oracle.
fn lift(message: u128, t: u128, embedding: PlaintextEmbedding) -> (u128, bool) {
    if embedding == PlaintextEmbedding::Centered && message >= t.div_ceil(2) {
        (t - message, true)
    } else {
        (message, false)
    }
}

fn apply_sign(value: u128, negative: bool, q: u128) -> u128 {
    let value = value % q;
    if negative && value != 0 {
        q - value
    } else {
        value
    }
}

fn rounded_oracle(message: u128, t: u128, q: u128, embedding: PlaintextEmbedding) -> u128 {
    let (magnitude, negative) = lift(message, t, embedding);
    apply_sign(round_half_up(magnitude * q, t), negative, q)
}

fn scaled_oracle(message: u128, t: u128, q: u128, embedding: PlaintextEmbedding) -> u128 {
    let (magnitude, negative) = lift(message, t, embedding);
    apply_sign(magnitude * round_half_up(q, t), negative, q)
}

fn to_value<T: TryFrom<u128>>(value: u128) -> T {
    T::try_from(value).ok().unwrap()
}

// Exhaust small domains; otherwise cover zero, both centered halves and t-1.
fn messages(t: u128) -> Vec<u128> {
    if t <= 16 {
        (0..t).collect()
    } else {
        vec![0, 1, t.div_ceil(2) - 1, t.div_ceil(2), t - 1]
    }
}

// Exercise each numeric strategy with Native or Uint at all three word sizes.
fn check_encoding<T: FheUint + Into<u128> + TryFrom<u128>>(t: u128, q: u128) {
    if q == 1u128 << T::BITS {
        check_encoding_with::<T, _>(t, q, NativeModulus::new());
    } else {
        check_encoding_with::<T, _>(t, q, UintModulus::new(to_value(q)));
    }
}

fn check_encoding_with<
    T: FheUint + Into<u128> + TryFrom<u128>,
    M: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
>(
    t: u128,
    q: u128,
    modulus: M,
) {
    let rounded = RoundedCodec::new(to_value(t), modulus);
    // Fixed scaling requires a stricter recovery bound than per-message rounding.
    let delta = round_half_up(q, t);
    let scaled =
        (2 * (t * delta).abs_diff(q) * (t - 1) < q).then(|| ScaledCodec::new(to_value(t), modulus));
    let messages: Vec<T> = messages(t).into_iter().map(to_value).collect();

    for embedding in [PlaintextEmbedding::Unsigned, PlaintextEmbedding::Centered] {
        let expected: Vec<T> = messages
            .iter()
            .map(|&m| to_value(rounded_oracle(m.into(), t, q, embedding)))
            .collect();
        let expected_acc: Vec<T> = expected
            .iter()
            .map(|&c| to_value((q - 1 + c.into()) % q))
            .collect();
        // Check scalar results, output reuse, aliasing and modular accumulation.
        let mut output = vec![T::ZERO; messages.len()];
        rounded.encode_slice_to(&messages, &mut output, embedding);
        assert_eq!(output, expected, "t={t}, q={q}, embedding={embedding:?}");
        let mut inplace = messages.clone();
        rounded.encode_slice_assign(&mut inplace, embedding);
        assert_eq!(inplace, expected);
        let mut acc = vec![to_value(q - 1); messages.len()];
        rounded.add_encode_slice_assign(&mut acc, &messages, embedding);
        assert_eq!(acc, expected_acc);
        for ((&m, &encoded), &accumulated) in messages.iter().zip(&expected).zip(&expected_acc) {
            assert_eq!(rounded.encode_value(m, embedding), encoded);
            let mut scalar_acc = to_value(q - 1);
            rounded.add_encode_value_assign(&mut scalar_acc, m, embedding);
            assert_eq!(scalar_acc, accumulated);
        }

        if let Some(scaled) = scaled {
            let expected: Vec<T> = messages
                .iter()
                .map(|&m| to_value(scaled_oracle(m.into(), t, q, embedding)))
                .collect();
            scaled.encode_slice_to(&messages, &mut output, embedding);
            assert_eq!(output, expected, "t={t}, q={q}, embedding={embedding:?}");
            inplace.copy_from_slice(&messages);
            scaled.encode_slice_assign(&mut inplace, embedding);
            assert_eq!(inplace, expected);
            acc.fill(to_value(q - 1));
            scaled.add_encode_slice_assign(&mut acc, &messages, embedding);
            for ((&m, &encoded), &actual) in messages.iter().zip(&expected).zip(&acc) {
                assert_eq!(scaled.encode_value(m, embedding), encoded);
                assert_eq!(actual.into(), (q - 1 + encoded.into()) % q);
            }
            // Check the constructor's noiseless recovery guarantee. The shared
            // decoder's rounding boundaries are checked separately below.
            scaled.decode_slice_assign(&mut output);
            assert_eq!(output, messages);
        }
    }
}

#[test]
fn encoding_matches_integer_oracle() {
    fn check<T: FheUint + Into<u128> + TryFrom<u128>>() {
        let native = 1u128 << T::BITS;
        for (t, q) in [
            (256, native),     // Native power-of-two scale.
            (256, native / 2), // Explicit power-of-two scale.
            (7, native),
            (7, native - 1),
            (2, 4),  // The centered message 1 represents -1.
            (4, 14), // Fixed scale rounds a tie upward.
            (9, 18), // Exact shift with a non-power-of-two plaintext modulus.
            (9, 45), // Exact non-power-of-two scale.
            (7, 128),
            (7, 131),
            (16, 131), // Rounded scale is a power of two, but q/t is not integral.
            (12, 17),  // Valid only for per-message rounding.
        ] {
            check_encoding::<T>(t, q);
        }
    }
    check::<u16>();
    check::<u32>();
    check::<u64>();
    // Keep a masked accumulator and a compact modulus with a cached reciprocal.
    check_encoding_with(7, 128, PowOf2Modulus::new(128u64));
    check_encoding_with(16, 131, BarrettModulus::new(131u64));
}

#[test]
fn rounded_remainder_width_boundaries() {
    fn check<T: FheUint + Into<u128> + TryFrom<u128>>() {
        let native = 1u128 << T::BITS;
        let root = 1u128 << (T::BITS / 2);
        for (t, q) in [
            (root + 1, 3 * root + 1),     // (t-1)*(q%t) fits T.
            (root + 1, 3 * root + 2),     // The residual product overflows T.
            (root + 2, 3 * root + 3),     // Product fits, but adding t/2 overflows.
            (native / 2 + 1, native),     // Native wide fallback.
            (native / 2 + 1, native - 1), // Explicit wide fallback.
        ] {
            check_encoding::<T>(t, q);
        }
    }
    check::<u16>();
    check::<u32>();
    check::<u64>();
}

#[test]
fn decoding_matches_integer_oracle() {
    fn check<T: FheUint + Into<u128> + TryFrom<u128>>() {
        let native = 1u128 << T::BITS;
        for (t, q) in [
            (256, native),
            (256, native / 2),
            (native / 2, native), // Shift by one, including wraparound at q-1.
            (9, 18),              // Shift followed by reduction modulo non-power-of-two t.
            (9, 45),              // Exact division.
            (7, native),          // Native high-word rounding.
            (16, 131),
            (11, (native - 1) / 11), // Compact modulus with a wide biased product.
            (2, native / 2 - 1),     // Noncompact odd q; q*t fits in one word.
            (2, native / 2 + 1),     // Same strategy except q*t requires two words.
            (7, native - 1),
        ] {
            if q == native {
                check_decode::<T, _>(t, q, NativeModulus::new());
            } else {
                check_decode::<T, _>(t, q, UintModulus::new(to_value(q)));
            }
        }
    }
    check::<u16>();
    check::<u32>();
    check::<u64>();
    check_decode(7, 128, PowOf2Modulus::new(128u64));
    check_decode(16, 131, BarrettModulus::new(131u64));
    let wide_barrett_q = u64::MAX / 11;
    check_decode(
        11,
        wide_barrett_q.into(),
        BarrettModulus::new(wide_barrett_q),
    );

    check_decoder_binding(7, 1u128 << u64::BITS, NativeModulus::new());
    check_decoder_binding(16, 131, BarrettModulus::new(131));
}

// Decoder cells are tested at their integer boundaries; exact encode/decode
// round-trips alone would miss the tie direction and wrap from t-1 to zero.
fn decoding_phases(t: u128, q: u128) -> Vec<u128> {
    if q <= 256 {
        (0..q).collect()
    } else {
        // The first integer phase rounding up from m to m+1 is
        // ceil((2m+1)*q/(2t)); test both sides, including the last cell.
        let mut phases: Vec<_> = messages(t)
            .into_iter()
            .flat_map(|m| {
                let boundary = ((2 * m + 1) * q).div_ceil(2 * t);
                [boundary - 1, boundary % q, (boundary + 1) % q]
            })
            .collect();
        phases.extend([0, q - 1]);
        phases.sort_unstable();
        phases.dedup();
        phases
    }
}

fn decode_reference<T: TryFrom<u128>>(t: u128, q: u128) -> (Vec<T>, Vec<T>) {
    let phases = decoding_phases(t, q);
    let expected: Vec<T> = phases
        .iter()
        .map(|&c| to_value(round_half_up(c * t, q) % t))
        .collect();
    (phases.into_iter().map(to_value).collect(), expected)
}

fn check_decode<
    T: FheUint + Into<u128> + TryFrom<u128>,
    M: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
>(
    t: u128,
    q: u128,
    modulus: M,
) {
    let codec = RoundedCodec::<T, _>::new(to_value(t), modulus);
    let (phases, expected) = decode_reference(t, q);
    let mut output = vec![T::MAX; phases.len()];
    codec.decode_slice_to(&phases, &mut output);
    assert_eq!(output, expected, "t={t}, q={q}");
    for (&phase, &decoded) in phases.iter().zip(&expected) {
        assert_eq!(codec.decode_value(phase), decoded);
    }
    let mut inplace = phases;
    codec.decode_slice_assign(&mut inplace);
    assert_eq!(inplace, expected);
}

// Both owners expose the same decoder. Check representative native and
// explicit bindings separately from the full arithmetic matrix.
fn check_decoder_binding<M: ReduceAdd<u64, Output = u64> + PrepareModulusSwitch<ValueT = u64>>(
    t: u64,
    q: u128,
    modulus: M,
) {
    let rounded = RoundedCodec::new(t, modulus);
    let scaled = ScaledCodec::new(t, modulus);
    let (phases, expected) = decode_reference(t.into(), q);
    let mut output = vec![u64::MAX; phases.len()];
    for decoder in [
        MessageDecoder::from(&rounded),
        MessageDecoder::from(&scaled),
    ] {
        assert_eq!(decoder.plaintext_modulus(), t);
        assert_eq!(decoder.ciphertext_modulus(), modulus);
        output.fill(u64::MAX);
        decoder.decode_slice_to(&phases, &mut output);
        assert_eq!(output, expected);
        for (&phase, &decoded) in phases.iter().zip(&expected) {
            assert_eq!(decoder.decode_value(phase), decoded);
        }
        output.copy_from_slice(&phases);
        decoder.decode_slice_assign(&mut output);
        assert_eq!(output, expected);
    }
}

#[test]
fn rejects_invalid_messages_before_batch_writes() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let rounded = RoundedCodec::new(7u64, UintModulus::new(131));
    let scaled = ScaledCodec::new(7u64, UintModulus::new(131));
    let embedding = PlaintextEmbedding::Centered;
    let mut output = [1, 2];
    assert!(
        catch_unwind(AssertUnwindSafe(|| rounded.add_encode_slice_assign(
            &mut output,
            &[0, 7],
            embedding
        )))
        .is_err()
    );
    assert_eq!(output, [1, 2]);
    assert!(catch_unwind(|| rounded.encode_value(7, embedding)).is_err());
    assert!(catch_unwind(|| scaled.encode_value(7, embedding)).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(|| rounded.encode_slice_to(
            &[0, 7],
            &mut output,
            embedding
        )))
        .is_err()
    );
    assert_eq!(output, [1, 2]);
    assert!(
        catch_unwind(AssertUnwindSafe(|| scaled.add_encode_slice_assign(
            &mut output,
            &[0, 7],
            embedding
        )))
        .is_err()
    );
    assert_eq!(output, [1, 2]);
}

#[test]
fn rejects_invalid_modulus_pairs() {
    use primus_encoding::CodecError;

    for t in [0u64, 1] {
        assert_eq!(
            RoundedCodec::try_new(t, NativeModulus::new()).err(),
            Some(CodecError::InvalidPlaintextModulus)
        );
        assert_eq!(
            ScaledCodec::try_new(t, NativeModulus::new()).err(),
            Some(CodecError::InvalidPlaintextModulus)
        );
    }
    for (t, q) in [(0u64, 17), (1, 17), (2, 2), (3, 2)] {
        let expected = if t < 2 {
            CodecError::InvalidPlaintextModulus
        } else {
            CodecError::CiphertextModulusTooSmall
        };
        assert_eq!(
            RoundedCodec::try_new(t, UintModulus::new(q)).err(),
            Some(expected)
        );
        assert_eq!(
            ScaledCodec::try_new(t, UintModulus::new(q)).err(),
            Some(expected)
        );
    }
    // This pair meets q > t but violates fixed-scale recovery.
    assert_eq!(
        ScaledCodec::try_new(12u64, UintModulus::new(17)).err(),
        Some(CodecError::InsufficientScaleRecovery)
    );
}
