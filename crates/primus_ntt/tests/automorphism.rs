use primus_modulus::BarrettModulus;
use primus_ntt::{NttAutomorphismPermutation, NttTable, UintNttTable};
use primus_poly::CoeffAutomorphismPermutation;
use primus_shape::PolyLength;

#[test]
fn ntt_permutation_matches_coefficient_automorphism() {
    const Q: u32 = 257;
    let modulus = BarrettModulus::new(Q);
    // All odd degrees at N=32/64 cover sign changes and bit-reversed indices.
    // Transform kernel dispatch is checked in ntt.rs, independently of this map.
    for log_n in [5u32, 6] {
        let n = 1 << log_n;
        let poly_length = PolyLength::new(n);
        let ntt = UintNttTable::new(poly_length, modulus).unwrap();
        let input: Vec<u32> = (0..n).map(|index| (19 * index as u32 + 5) % Q).collect();
        let mut input_ntt = input.clone();
        ntt.transform_slice(&mut input_ntt);
        for degree in (1..2 * n).step_by(2) {
            let coefficient = CoeffAutomorphismPermutation::new(degree, poly_length);
            let permutation = NttAutomorphismPermutation::new(degree, poly_length);
            assert_eq!(permutation.poly_length().get(), n);
            let mut expected = vec![0; n];
            coefficient.apply_to(&input, &mut expected, modulus);
            ntt.transform_slice(&mut expected);
            let mut actual = vec![0; n];
            permutation.apply_to(&input_ntt, &mut actual);
            assert_eq!(actual, expected, "n={n}, degree={degree}");
        }
    }
    for (degree, n) in [(0, 32), (2, 32), (65, 32)] {
        assert!(
            std::panic::catch_unwind(|| NttAutomorphismPermutation::new(
                degree,
                PolyLength::new(n)
            ))
            .is_err()
        );
    }
}
