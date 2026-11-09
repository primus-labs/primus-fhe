//! RNS block traversal with distinct residues and factors in each modulus.

#![cfg(feature = "rns")]

use primus_factor::ShoupFactor;
use primus_lattice::ggsw::{CrtGgsw, DcrtGgsw};
use primus_modulus::BarrettModulus;

#[test]
fn rns_arithmetic_preserves_component_and_modulus_order() {
    const N: usize = 2;
    let qs = [17u32, 97];
    let moduli = qs.map(BarrettModulus::new);
    let rns_poly_len = N * qs.len();

    // Three gadget rows, two levels, three components, then modulus/coefficient.
    let len = rns_poly_len * (3 * 2 * 3);
    let lhs: Vec<u32> = (0..len)
        .map(|i| {
            let q = qs[i / N % qs.len()];
            if i % 2 == 0 { (i as u32) % q } else { q - 1 }
        })
        .collect();
    let rhs: Vec<u32> = (0..len)
        .map(|i| (i as u32 + 2) % qs[i / N % qs.len()])
        .collect();
    let expected = |op: fn(u32, u32, u32) -> u32| -> Vec<u32> {
        lhs.iter()
            .zip(&rhs)
            .enumerate()
            .map(|(i, (&a, &b))| {
                let limb = i / N % qs.len();
                op(a, b, qs[limb])
            })
            .collect()
    };
    let input = CrtGgsw::new(lhs.as_slice());
    let rhs = CrtGgsw::new(rhs.as_slice());
    let mut storage = vec![11; len];
    let mut output = CrtGgsw::new(storage.as_mut_slice());
    input.add_to(&rhs, &mut output, N, rns_poly_len, &moduli);
    assert_eq!(output.as_ref(), expected(|a, b, q| (a + b) % q));
    output.sub_assign(&rhs, N, rns_poly_len, &moduli);
    assert_eq!(output.as_ref(), lhs);
    input.sub_to(&rhs, &mut output, N, rns_poly_len, &moduli);
    assert_eq!(output.as_ref(), expected(|a, b, q| (a + q - b) % q));
    output.add_assign(&rhs, N, rns_poly_len, &moduli);
    assert_eq!(output.as_ref(), lhs);
    input.neg_to(&mut output, N, rns_poly_len, &moduli);
    assert_eq!(output.as_ref(), expected(|a, _, q| (q - a) % q));
    output.neg_assign(N, rns_poly_len, &moduli);
    assert_eq!(output.as_ref(), lhs);
}

#[test]
fn rns_scalar_and_factor_products_preserve_accumulators_and_modulus_order() {
    use primus_rns::{ResidueFactors, Residues};
    // Four coefficients distinguish within-polynomial and modulus boundaries;
    // SIMD lane/tail coverage is already owned by the arithmetic crates.
    const N: usize = 4;
    let qs = [17u32, 97];
    let moduli = qs.map(BarrettModulus::new);
    let rns_poly_len = N * qs.len();
    let len = rns_poly_len * (3 * 2 * 3);
    let values: Vec<u32> = (0..len).map(|i| i as u32 * 31 % qs[i / N % 2]).collect();
    let acc: Vec<u32> = (0..len)
        .map(|i| (i as u32 * 7 + 11) % qs[i / N % 2])
        .collect();
    let input = DcrtGgsw::new(values.as_slice());
    let mut storage = vec![11; len];
    let mut output = DcrtGgsw::new(storage.as_mut_slice());
    for scalars in [[0, 0], [3, 5], [16, 96]] {
        let factors = ResidueFactors([
            ShoupFactor::new(scalars[0], qs[0]),
            ShoupFactor::new(scalars[1], qs[1]),
        ]);
        let scalar = Residues(scalars);
        let product: Vec<_> = values
            .iter()
            .enumerate()
            .map(|(i, x)| x * scalars[i / N % 2] % qs[i / N % 2])
            .collect();
        let sum: Vec<_> = acc
            .iter()
            .zip(&product)
            .enumerate()
            .map(|(i, (a, p))| (a + p) % qs[i / N % 2])
            .collect();
        let difference: Vec<_> = acc
            .iter()
            .zip(&product)
            .enumerate()
            .map(|(i, (a, p))| (a + qs[i / N % 2] - p) % qs[i / N % 2])
            .collect();
        output.as_mut().fill(11);
        input.mul_factor_to(&factors, &mut output, N, rns_poly_len, &qs);
        assert_eq!(output.as_ref(), product);
        output.as_mut().copy_from_slice(&values);
        output.mul_factor_assign(&factors, N, rns_poly_len, &qs);
        assert_eq!(output.as_ref(), product);
        output.as_mut().fill(11);
        input.mul_scalar_to(&scalar, &mut output, N, rns_poly_len, &moduli);
        assert_eq!(output.as_ref(), product);
        output.as_mut().copy_from_slice(&values);
        output.mul_scalar_assign(&scalar, N, rns_poly_len, &moduli);
        assert_eq!(output.as_ref(), product);
        output.as_mut().copy_from_slice(&acc);
        output.add_mul_scalar_assign(&input, &scalar, N, rns_poly_len, &moduli);
        assert_eq!(output.as_ref(), sum);
        output.as_mut().copy_from_slice(&acc);
        output.add_mul_factor_assign(&input, &factors, N, rns_poly_len, &qs);
        assert_eq!(output.as_ref(), sum);
        output.as_mut().copy_from_slice(&acc);
        output.sub_mul_factor_assign(&input, &factors, N, rns_poly_len, &qs);
        assert_eq!(output.as_ref(), difference);
    }
}
