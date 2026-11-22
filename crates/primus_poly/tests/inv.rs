use primus_modulus::BarrettModulus;
use primus_poly::DcrtPolynomial;
use primus_reduce::ReduceError;

// Reducer tests cover a single slice. DCRT pairs each slice with its own modulus.
#[test]
fn dcrt_inverse_preserves_modulus_order_and_reports_failing_component() {
    let moduli = [BarrettModulus::new(17u32), BarrettModulus::new(19u32)];
    let input = DcrtPolynomial::new(vec![1, 2, 3, 4, 5, 6]);
    let mut output = DcrtPolynomial::new(vec![u32::MAX; 6]);

    input.inv_to(&mut output, 3, &moduli);

    assert_eq!(output.as_slice(), &[1, 9, 6, 5, 4, 16]);

    // Failure in the second limb must report q_1, not q_0.
    let input = DcrtPolynomial::new(vec![1, 2, 3, 4, 0, 6]);

    assert_eq!(
        input.try_inv_to(&mut output, 3, &moduli),
        Err(ReduceError::NoInverse {
            value: 0,
            modulus: 19,
        })
    );
}
