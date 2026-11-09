//! Integer oracle for the coupled sum/difference outputs, modulus-major factor
//! packing, and the SIMD tail. The same test runs with and without SIMD.

use primus_factor::{Factor, ShoupFactor};
use primus_integer::FheUint;
use primus_poly::DcrtPolynomial;

// Seventeen points include full u32/u64 SIMD vectors and a scalar tail in each
// limb. These raw pointwise operations do not require a power-of-two ring length.
fn check<T>(qs: [T; 2])
where
    T: FheUint + Into<u64>,
    ShoupFactor<T>: Factor<T>,
{
    const N: usize = 17;
    let len = N * qs.len();
    let values = |offset: usize| -> Vec<T> {
        (0..len)
            .map(|index| {
                let q = u128::from(qs[index / N].into());
                let value = match (index + offset) % 4 {
                    0 => 0,
                    1 => q - 1,
                    _ => (index as u128 * 0x9e37_79b9 + offset as u128) % q,
                };
                T::as_from(value as u64)
            })
            .collect()
    };
    let mut lhs = DcrtPolynomial::new(values(0));
    let rhs = DcrtPolynomial::new(values(1));
    let weights = DcrtPolynomial::new(values(2));
    let factors: Vec<_> = weights
        .as_ref()
        .iter()
        .enumerate()
        .map(|(index, &w)| ShoupFactor::new(w, qs[index / N]))
        .collect();
    let mut factor_output = vec![T::ONE; len + 2];

    // A second call verifies reuse of both outputs with the updated sum as lhs.
    for _ in 0..2 {
        let mut expected_sum = Vec::with_capacity(len);
        let mut expected_product = Vec::with_capacity(len);
        for index in 0..len {
            let q = u128::from(qs[index / N].into());
            let a = u128::from(lhs.as_ref()[index].into());
            let b = u128::from(rhs.as_ref()[index].into());
            let w = u128::from(weights.as_ref()[index].into());
            expected_sum.push(T::as_from(((a + b) % q) as u64));
            expected_product.push(T::as_from((((a + q - b) % q * w) % q) as u64));
        }

        lhs.as_mut_view().butterfly_mul_factor_to(
            &rhs.as_view(),
            &factors,
            &mut DcrtPolynomial::new(&mut factor_output[1..len + 1]),
            N,
            &qs,
        );
        assert_eq!(lhs.as_ref(), expected_sum);
        assert_eq!(&factor_output[1..len + 1], expected_product);
        assert_eq!(factor_output[0], T::ONE);
        assert_eq!(factor_output[len + 1], T::ONE);
    }
}

#[test]
fn factor_butterfly_preserves_original_lhs_modulus_order_and_tail() {
    check([132_120_577u32, 754_974_721]);
    check([1_152_921_504_606_830_593u64, 576_460_752_303_439_873]);
}
