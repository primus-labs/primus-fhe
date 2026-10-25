use primus_distr::SecretKeyDistr;

/// Reject nonfinite/out-of-range probabilities and ternary sums above one.
#[test]
fn probability_constructors_check_individual_values_and_sum() {
    use std::panic::catch_unwind;

    for probability in [0.0, 0.3, 1.0] {
        let _ = SecretKeyDistr::binary(probability);
    }
    for (negative, positive) in [(0.0, 0.0), (0.0, 1.0), (1.0, 0.0), (0.25, 0.75)] {
        let _ = SecretKeyDistr::ternary(negative, positive);
    }
    for probability in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 1.1] {
        assert!(catch_unwind(|| SecretKeyDistr::binary(probability)).is_err());
        assert!(catch_unwind(|| SecretKeyDistr::ternary(probability, 0.0)).is_err());
        assert!(catch_unwind(|| SecretKeyDistr::ternary(0.0, probability)).is_err());
    }
    assert!(catch_unwind(|| SecretKeyDistr::ternary(0.6, 0.5)).is_err());
}

/// Check empty/exact-bound keys and reject overfull or overflowing compositions.
#[test]
fn fixed_weight_constructors_check_complete_key_length() {
    use std::panic::catch_unwind;

    for (length, weight) in [(0, 0), (7, 0), (7, 7)] {
        let _ = SecretKeyDistr::fixed_hamming_weight_binary(length, weight);
        let _ = SecretKeyDistr::fixed_hamming_weight_ternary(length, weight);
    }
    for (length, negative, positive) in [(0, 0, 0), (7, 0, 7), (7, 3, 4)] {
        let _ = SecretKeyDistr::fixed_composition_ternary(length, negative, positive);
    }
    assert!(catch_unwind(|| SecretKeyDistr::fixed_hamming_weight_binary(7, 8)).is_err());
    assert!(catch_unwind(|| SecretKeyDistr::fixed_hamming_weight_ternary(7, 8)).is_err());
    for (length, negative, positive) in [(7, 4, 4), (7, 8, 0), (usize::MAX, usize::MAX, 1)] {
        assert!(
            catch_unwind(|| SecretKeyDistr::fixed_composition_ternary(length, negative, positive))
                .is_err()
        );
    }
}
