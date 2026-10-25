//! Single-modulus arithmetic: borrowed outputs and fused product semantics.

use primus_factor::ShoupFactor;
use primus_lattice::lwe::Lwe;
use primus_modulus::BarrettModulus;

#[test]
fn borrowed_lwe_arithmetic_overwrites_output_across_modulus_boundary() {
    let modulus = BarrettModulus::new(97u32);
    let lhs = [0, 96, 45, 80];
    let rhs = [1, 2, 45, 30];

    let lhs = Lwe::new(lhs.as_slice());
    let rhs = Lwe::new(rhs.as_slice());
    let mut storage = [42; 4];
    let mut output = Lwe::new(storage.as_mut_slice());
    lhs.add_to(&rhs, &mut output, modulus);
    assert_eq!(output.as_ref(), &[1, 1, 90, 13]);
    output.as_mut().fill(42);
    lhs.sub_to(&rhs, &mut output, modulus);
    assert_eq!(output.as_ref(), &[96, 94, 0, 50]);
    lhs.neg_to(&mut output, modulus);
    assert_eq!(output.as_ref(), &[0, 1, 52, 17]);
}

#[test]
fn scalar_and_factor_products_preserve_overwrite_and_accumulation_semantics() {
    const Q: u32 = 97;
    // Flat arithmetic is shared by the wrappers; an odd length also exercises SIMD tails.
    let values: Vec<u32> = (0..65).map(|i| i as u32 * 31 % Q).collect();
    let input = Lwe::new(values.as_slice());
    // Offset the output within aligned backing storage: kernels may not assume
    // caller-provided slices share the alignment of workspace-owned buffers.
    let mut storage = aligned_vec::avec![u32::MAX; values.len() + 2];
    let mut output = Lwe::new(&mut storage[1..=values.len()]);
    let acc: Vec<_> = (0..values.len()).map(|i| (i as u32 * 7 + 11) % Q).collect();
    for scalar in [0, 3, Q - 1] {
        let factor = ShoupFactor::new(scalar, Q);
        let expected: Vec<_> = values.iter().map(|x| x * scalar % Q).collect();
        output.as_mut().fill(11);
        input.mul_factor_to(factor, &mut output, Q);
        assert_eq!(output.as_ref(), expected);
        output.as_mut().copy_from_slice(&values);
        output.mul_factor_assign(factor, Q);
        assert_eq!(output.as_ref(), expected);
        output.as_mut().copy_from_slice(&acc);
        output.add_mul_factor_assign(&input, factor, Q);
        let sum: Vec<_> = acc
            .iter()
            .zip(&expected)
            .map(|(a, p)| (a + p) % Q)
            .collect();
        assert_eq!(output.as_ref(), sum);
        output.as_mut().copy_from_slice(&acc);
        output.sub_mul_factor_assign(&input, factor, Q);
        let difference: Vec<_> = acc
            .iter()
            .zip(&expected)
            .map(|(a, p)| (a + Q - p) % Q)
            .collect();
        assert_eq!(output.as_ref(), difference);
        let modulus = BarrettModulus::new(Q);
        output.as_mut().fill(11);
        input.mul_scalar_to(scalar, &mut output, modulus);
        assert_eq!(output.as_ref(), expected);
        output.as_mut().copy_from_slice(&values);
        output.mul_scalar_assign(scalar, modulus);
        assert_eq!(output.as_ref(), expected);
        output.as_mut().copy_from_slice(&acc);
        output.add_mul_scalar_assign(&input, scalar, modulus);
        assert_eq!(output.as_ref(), sum);
        output.as_mut().copy_from_slice(&acc);
        output.sub_mul_scalar_assign(&input, scalar, modulus);
        assert_eq!(output.as_ref(), difference);
    }
    assert_eq!([storage[0], storage[values.len() + 1]], [u32::MAX; 2]);
}
