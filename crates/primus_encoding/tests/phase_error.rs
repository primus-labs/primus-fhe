//! Phase diagnostics use an explicit reference and exact integer distances.

use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_encoding::{
    PlaintextEmbedding, RoundedCodec, ScaledCodec, phase_error_magnitude,
    phase_error_magnitude_slice_to,
};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::ReduceSub;

// A representable u128 modulus gives an independent oracle even for Native64.
// Adjacent large residues also catch a premature conversion to floating point.
fn check_distances<T, M>(q: u128, modulus: M)
where
    T: FheUint + TryFrom<u128>,
    M: Copy + ReduceSub<T, Output = T>,
{
    let values = [0, 1, q / 2 - 1, q / 2, q / 2 + 1, q - 2, q - 1];
    let phases = values.map(|value| T::try_from(value).ok().unwrap());
    for reference in values {
        let expected_phase = T::try_from(reference).ok().unwrap();
        let expected = values.map(|phase| {
            let distance = phase.abs_diff(reference);
            T::try_from(distance.min(q - distance)).ok().unwrap()
        });
        let mut output = [T::MAX; 7];
        phase_error_magnitude_slice_to(&phases, &[expected_phase; 7], &mut output, modulus);
        assert_eq!(output, expected, "q={q}, reference={reference}");
        for (&phase, expected) in phases.iter().zip(expected) {
            assert_eq!(
                phase_error_magnitude(phase, expected_phase, modulus),
                expected,
                "q={q}, phase={phase:?}, reference={reference}"
            );
        }
    }
}

#[test]
fn circular_distance_matches_wide_integer_oracle() {
    fn check<T: FheUint + TryFrom<u128>>() {
        let native = 1u128 << T::BITS;
        check_distances::<T, _>(native, NativeModulus::new());
        check_distances::<T, _>(256, PowOf2Modulus::new(T::as_from(256u32)));
        check_distances::<T, _>(131, BarrettModulus::new(T::as_from(131u32)));
        check_distances::<T, _>(native - 1, UintModulus::new(T::MAX));
    }
    check::<u32>();
    check::<u64>();
}

#[test]
fn reference_uses_expected_message_and_embedding() {
    // A wrong decoded codeword has zero residual but a nonzero reference error.
    let modulus = PowOf2Modulus::new(256u64);
    let codec = RoundedCodec::new(4, modulus);
    let phase = 64;
    let decoded = codec.decode_value(phase);
    assert_eq!(decoded, 1);
    let reencoded = codec.encode_value(decoded, PlaintextEmbedding::Unsigned);
    assert_eq!(phase_error_magnitude(phase, reencoded, modulus), 0);
    let expected = codec.encode_value(0, PlaintextEmbedding::Unsigned);
    assert_eq!(phase_error_magnitude(phase, expected, modulus), 64);

    // Fixed rounded scaling can give different references for the same residue.
    let modulus = BarrettModulus::new(131u64);
    let codec = ScaledCodec::new(7, modulus);
    for (embedding, expected, magnitude) in [
        (PlaintextEmbedding::Unsigned, 114, 1),
        (PlaintextEmbedding::Centered, 112, 3),
    ] {
        let reference = codec.encode_value(6, embedding);
        assert_eq!(reference, expected);
        assert_eq!(phase_error_magnitude(115, reference, modulus), magnitude);
    }
}

#[test]
fn slice_requires_exact_lengths_before_writing() {
    let phase = [0u64, 255];
    let expected = [1, 0];
    let modulus = PowOf2Modulus::new(256);
    // Neither a longer nor a shorter slice may be silently truncated by zip.
    for (phase_len, expected_len, output_len) in [(2, 1, 2), (1, 2, 1), (2, 2, 1), (1, 1, 2)] {
        let mut output = [99; 2];
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                phase_error_magnitude_slice_to(
                    &phase[..phase_len],
                    &expected[..expected_len],
                    &mut output[..output_len],
                    modulus,
                );
            }))
            .is_err()
        );
        assert_eq!(output, [99; 2]);
    }
    phase_error_magnitude_slice_to::<u64, _>(&[], &[], &mut [], modulus);
}
