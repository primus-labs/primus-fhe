use primus_modulus::is_prime_u64;

#[test]
fn primality_covers_small_oracle_pseudoprimes_and_full_word_boundary() {
    for n in 0u64..4096 {
        let expected = n >= 2
            && !(2..)
                .take_while(|d| d * d <= n)
                .any(|d| n.is_multiple_of(d));
        assert_eq!(is_prime_u64(n), expected, "n={n}");
    }
    for composite in [341_550_071_728_321, 3_825_123_056_546_413_051, u64::MAX] {
        assert!(!is_prime_u64(composite));
    }
    for prime in [2_305_843_009_213_693_951, 18_446_744_073_709_551_557] {
        assert!(is_prime_u64(prime));
    }
}
