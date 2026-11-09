use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::CoeffAutomorphismPermutation;
use primus_shape::PolyLength;

#[test]
fn coefficient_permutation_matches_monomial_substitution() {
    const Q: u32 = 257;
    let modulus = BarrettModulus::new(Q);
    // Exhaust all odd degrees, including identity and the N+1 sign-only path,
    // at the minimum size and with an additional index bit.
    for n in [32, 64] {
        let input: Vec<i32> = (0..n).map(|i| i as i32 - n as i32 / 2).collect();
        let residues: Vec<u32> = input
            .iter()
            .map(|&x| x.rem_euclid(Q as i32) as u32)
            .collect();
        for degree in (1..2 * n).step_by(2) {
            let permutation = CoeffAutomorphismPermutation::new(degree, PolyLength::new(n));
            assert_eq!(permutation.poly_length().get(), n);
            let mut expected = vec![0i32; n];
            // Independent scatter oracle in the coefficient ring.
            for (i, &value) in input.iter().enumerate() {
                let power = i * degree;
                expected[power % n] = if power / n % 2 == 0 { value } else { -value };
            }
            let mut signed = vec![i32::MAX; n];
            permutation.apply_signed_to::<u32>(&input, &mut signed);
            assert_eq!(signed, expected);
            let mut output = vec![u32::MAX; n];
            permutation.apply_to(&residues, &mut output, modulus);
            for (actual, expected) in output.into_iter().zip(expected) {
                assert_eq!(actual, expected.rem_euclid(Q as i32) as u32);
            }
        }
    }
    // Full-width bit patterns use modular negation, not signed-key negation.
    for degree in [3, 33] {
        let permutation = CoeffAutomorphismPermutation::new(degree, PolyLength::new(32));
        let mut input = [0u32; 32];
        // Both degrees negate coefficient 17 after negacyclic reduction.
        input[17] = i32::MIN as u32;
        let mut output = [0; 32];
        permutation.apply_to(&input, &mut output, NativeModulus::new());
        let mut expected = [0; 32];
        expected[(17 * degree) % 32] = i32::MIN as u32;
        assert_eq!(output, expected);
    }

    // The gather's input-extent check also protects the release build.
    assert!(
        std::panic::catch_unwind(|| {
            let permutation = CoeffAutomorphismPermutation::new(3, PolyLength::new(32));
            let mut output = [0u32; 32];
            permutation.apply_to(&[0u32; 31], &mut output, modulus);
        })
        .is_err()
    );

    for (degree, n) in [(0, 32), (2, 32), (65, 32)] {
        assert!(
            std::panic::catch_unwind(|| CoeffAutomorphismPermutation::new(
                degree,
                PolyLength::new(n)
            ))
            .is_err()
        );
    }
}
