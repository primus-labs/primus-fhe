use primus_factor::{FactorBase, ShoupFactor};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_poly::{BigUintPolynomial, CrtPolynomial};
use primus_reduce::prelude::*;
use primus_rns::{BaseConverter, RNSBase, RNSError};

// Keep single-value coverage small: it only checks the basic CRT contract and
// the caller-provided output variants. Hot paths are covered by slice tests.
type ValueT = u64;
type ModulusT = BarrettModulus<ValueT>;
type BaseT = RNSBase<ValueT, ModulusT>;

// Shorthand to construct an RNSBase from raw moduli values. Panics on error
// since test moduli are always valid.
fn rns_base(moduli: &[ValueT]) -> BaseT {
    let moduli: Vec<_> = moduli.iter().copied().map(ModulusT::new).collect();
    RNSBase::new(&moduli).unwrap()
}

// Transpose residue vectors from value-major [value][modulus] to modulus-major
// flat layout [modulus_0_all_values, modulus_1_all_values, ...]. This matches
// the CRT layout convention used by the slice APIs.
fn pack_modulus_major(residues_by_value: &[Vec<ValueT>], moduli_count: usize) -> Vec<ValueT> {
    let value_count = residues_by_value.len();
    let mut packed = vec![0; moduli_count * value_count];

    for (value_index, residues) in residues_by_value.iter().enumerate() {
        assert_eq!(residues.len(), moduli_count);
        for (modulus_index, &residue) in residues.iter().enumerate() {
            packed[modulus_index * value_count + value_index] = residue;
        }
    }

    packed
}

// Compose each value's residues via the scalar compose API and pack the
// resulting BigUint digits into a flat buffer for the slice decompose tests.
fn compose_values(base: &BaseT, residues_by_value: &[Vec<ValueT>]) -> Vec<ValueT> {
    let value_len = base.big_uint_value_len();
    let mut values = vec![0; residues_by_value.len() * value_len];

    for (value_index, residues) in residues_by_value.iter().enumerate() {
        let composed = base.compose(residues);
        values[value_index * value_len..(value_index + 1) * value_len]
            .copy_from_slice(composed.digits());
    }

    values
}

// Reference formula for centered (wrapping) decomposition: values below
// ceil(small_modulus/2) stay unchanged; larger values are mapped to
// (modulus - small_modulus + value). mod-2 is treated as unsigned.
fn expected_wrapping(value: ValueT, small_modulus: ValueT, modulus: ValueT) -> ValueT {
    if small_modulus == 2 || value < small_modulus.div_ceil(2) {
        value
    } else {
        modulus - small_modulus + value
    }
}

// Passing an empty moduli slice should return EmptyBase error.
#[test]
fn construction_rejects_empty_base() {
    let moduli: [ModulusT; 0] = [];
    assert!(matches!(RNSBase::new(&moduli), Err(RNSError::EmptyBase)));
}

// Moduli that are not pairwise coprime (21 and 35 share gcd=7) should
// return CoPrimeError.
#[test]
fn construction_rejects_non_coprime_moduli() {
    let moduli = [21, 35].map(ModulusT::new);
    assert!(matches!(RNSBase::new(&moduli), Err(RNSError::CoPrimeError)));
}

// Smoke test for the single-value compose/decompose public API:
// compose, decompose, decompose_to, and compose_to should all roundtrip.
#[test]
fn single_value_apis_cover_basic_crt_contract() {
    let base = rns_base(&[3, 5, 7]);
    let residues = [2, 3, 2];

    let value = base.compose(&residues);
    assert_eq!(base.decompose(value.view()), residues);

    let mut decomposed = vec![ValueT::MAX; base.moduli_count()];
    base.decompose_to(value.view(), &mut decomposed);
    assert_eq!(decomposed, residues);

    let mut composed_to = BigUint(vec![ValueT::MAX; base.big_uint_value_len()]);
    {
        let mut composed_to_view = composed_to.view_mut();
        base.compose_to(&residues, &mut composed_to_view);
    }
    assert_eq!(composed_to, value);
}

// Batch slice APIs (decompose_big_uint_values_to / compose_multiple_values_to)
// use modulus-major CRT layout. This roundtrip test guards the layout contract
// and also covers the thin polynomial forwarding APIs (decompose_polynomial_to /
// compose_polynomial_to).
#[test]
fn slice_decompose_and_compose_roundtrip_modulus_major_layout() {
    let base = rns_base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    let residues_by_value = vec![
        vec![0, 0],
        vec![1, 2],
        vec![97, 131],
        vec![base.moduli()[0].value() - 1, base.moduli()[1].value() - 2],
        vec![123_456_789, 987_654_321],
    ];

    // The slice APIs use modulus-major CRT layout: each modulus owns a full
    // chunk of coefficients. This catches accidental value-major transposes.
    let expected_residues = pack_modulus_major(&residues_by_value, base.moduli_count());
    let big_uint_values = compose_values(&base, &residues_by_value);
    let value_count = residues_by_value.len();

    let mut decomposed = vec![ValueT::MAX; expected_residues.len()];
    base.decompose_big_uint_values_to(&big_uint_values, &mut decomposed, value_count);
    assert_eq!(decomposed, expected_residues);

    let mut recomposed = vec![ValueT::MAX; big_uint_values.len()];
    let mut scratch = vec![ValueT::MAX; base.moduli_count()];
    base.compose_multiple_values_to(
        &expected_residues,
        &mut recomposed,
        value_count,
        &mut scratch,
    );
    assert_eq!(recomposed, big_uint_values);

    // Polynomial wrappers are thin forwarding APIs; one roundtrip is enough to
    // guard their layout contract without duplicating every slice case.
    let big_poly = BigUintPolynomial::new(big_uint_values.clone());
    let mut crt_poly = CrtPolynomial::new(vec![ValueT::MAX; expected_residues.len()]);
    base.decompose_polynomial_to(&big_poly, &mut crt_poly, value_count);
    assert_eq!(crt_poly.as_slice(), expected_residues.as_slice());

    let crt_poly = CrtPolynomial::new(expected_residues.clone());
    let mut big_poly_out = BigUintPolynomial::new(vec![ValueT::MAX; big_uint_values.len()]);
    base.compose_polynomial_to(&crt_poly, &mut big_poly_out, value_count, &mut scratch);
    assert_eq!(big_poly_out.as_slice(), big_uint_values.as_slice());
}

// wrapping_decompose lifts a signed value modulo small_modulus into each RNS
// modulus using centered representation: values below small_modulus/2 stay
// unchanged, larger values are wrapped (modulus - small_modulus + value).
// Both the scalar APIs and the slice API are checked against that rule.
#[test]
fn wrapping_slice_decompose_matches_centered_scalar_rule() {
    let base = rns_base(&[97, 101, 103]);

    for small_modulus in [2, 7, 16] {
        let small_values: Vec<_> = (0..17).map(|i| (i * 5 + 3) % small_modulus).collect();
        let mut actual = vec![ValueT::MAX; base.moduli_count() * small_values.len()];

        base.wrapping_decompose_small_values_to(
            &small_values,
            &mut actual,
            small_values.len(),
            small_modulus,
        );

        let mut expected = vec![0; actual.len()];
        for (modulus_index, modulus) in base.moduli().iter().enumerate() {
            let modulus_value = modulus.value();
            for (value_index, &value) in small_values.iter().enumerate() {
                expected[modulus_index * small_values.len() + value_index] =
                    expected_wrapping(value, small_modulus, modulus_value);
            }
        }
        assert_eq!(actual, expected, "small_modulus={small_modulus}");

        for &value in &[0, small_modulus.div_ceil(2), small_modulus - 1] {
            let expected_scalar: Vec<_> = base
                .moduli()
                .iter()
                .map(|m| expected_wrapping(value, small_modulus, m.value()))
                .collect();
            assert_eq!(
                base.wrapping_decompose(value, small_modulus),
                expected_scalar
            );

            let mut out = vec![ValueT::MAX; base.moduli_count()];
            base.wrapping_decompose_to(value, &mut out, small_modulus);
            assert_eq!(out, expected_scalar);
        }
    }
}

// Fused multiply-add decompose: add_wrapping_decompose_small_values_scaled
// (centered) and add_decompose_small_values_scaled (unsigned). Each reads small
// values, multiplies by per-modulus factors (Shoup), and adds into an
// accumulator. Both variants are checked against an element-wise reference.
#[test]
fn scaled_slice_decompose_accumulates_against_reference_formula() {
    let base = rns_base(&[97, 101, 103]);
    let small_modulus = 7;
    let small_values: Vec<_> = (0..17).map(|i| (i * 3 + 1) % small_modulus).collect();
    let factor_values = [3, 5, 7];
    let factors: Vec<_> = factor_values
        .iter()
        .zip(base.moduli())
        .map(|(&factor, modulus)| ShoupFactor::new(factor, modulus.value()))
        .collect();

    // Use a non-zero accumulator so the test covers the fused add semantics,
    // not just multiplication by each per-modulus factor.
    let mut acc: Vec<_> = base
        .moduli()
        .iter()
        .enumerate()
        .flat_map(|(modulus_index, modulus)| {
            let modulus_value = modulus.value();
            (0..small_values.len()).map(move |value_index| {
                (11 + value_index as ValueT * 7 + modulus_index as ValueT) % modulus_value
            })
        })
        .collect();
    let original_acc = acc.clone();

    base.add_wrapping_decompose_small_values_scaled(
        &small_values,
        &mut acc,
        small_values.len(),
        small_modulus,
        &factors,
    );

    let mut expected = original_acc.clone();
    for (modulus_index, modulus) in base.moduli().iter().enumerate() {
        let modulus_value = modulus.value();
        for (value_index, &value) in small_values.iter().enumerate() {
            let centered = expected_wrapping(value, small_modulus, modulus_value);
            let product = modulus.reduce_mul(factor_values[modulus_index], centered);
            let index = modulus_index * small_values.len() + value_index;
            expected[index] = modulus.reduce_add(expected[index], product);
        }
    }
    assert_eq!(acc, expected);

    let mut unsigned_acc = original_acc;
    base.add_decompose_small_values_scaled(
        &small_values,
        &mut unsigned_acc,
        small_values.len(),
        &factors,
    );

    let mut expected_unsigned: Vec<_> = base
        .moduli()
        .iter()
        .enumerate()
        .flat_map(|(modulus_index, modulus)| {
            let modulus_value = modulus.value();
            (0..small_values.len()).map(move |value_index| {
                (11 + value_index as ValueT * 7 + modulus_index as ValueT) % modulus_value
            })
        })
        .collect();
    for (modulus_index, modulus) in base.moduli().iter().enumerate() {
        for (value_index, &value) in small_values.iter().enumerate() {
            let product = modulus.reduce_mul(factor_values[modulus_index], value);
            let index = modulus_index * small_values.len() + value_index;
            expected_unsigned[index] = modulus.reduce_add(expected_unsigned[index], product);
        }
    }
    assert_eq!(unsigned_acc, expected_unsigned);
}

// BaseConverter array APIs: fast_convert_array should match the per-value
// scalar fast_convert result coefficient by coefficient, and the pair iterator
// should produce matching (even-index, odd-index) pairs. exact_convert_array
// is checked on small canonical values against a trivial modulo reduction.
#[test]
fn base_converter_slice_apis_match_scalar_and_exact_reference() {
    let input_base = rns_base(&[17, 19, 23]);
    let output_base = rns_base(&[29, 31]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let residues_by_value = vec![
        vec![0, 0, 0],
        vec![1, 2, 3],
        vec![16, 18, 22],
        vec![7, 11, 13],
        vec![4, 0, 19],
    ];
    let value_count = residues_by_value.len();
    let crt_in = pack_modulus_major(&residues_by_value, input_base.moduli_count());

    // Fast conversion has its own approximate correction model; the array APIs
    // should match the scalar fast converter exactly, coefficient by coefficient.
    let mut expected_fast_out = vec![0; output_base.moduli_count() * value_count];
    for (value_index, residues) in residues_by_value.iter().enumerate() {
        let mut scalar_out = vec![ValueT::MAX; output_base.moduli_count()];
        let mut scalar_scratch = vec![ValueT::MAX; input_base.moduli_count()];
        converter.fast_convert(residues, &mut scalar_out, &mut scalar_scratch);

        for (modulus_index, residue) in scalar_out.into_iter().enumerate() {
            expected_fast_out[modulus_index * value_count + value_index] = residue;
        }
    }

    // Array conversion is the production path: one scratch buffer is filled in
    // coefficient-major order, then reduced into modulus-major output chunks.
    let mut crt_out = vec![ValueT::MAX; expected_fast_out.len()];
    let mut scratch = vec![ValueT::MAX; input_base.moduli_count() * value_count];
    converter.fast_convert_array(&crt_in, &mut crt_out, value_count, &mut scratch);
    assert_eq!(crt_out, expected_fast_out);

    let mut pair_scratch = vec![ValueT::MAX; input_base.moduli_count() * value_count];
    let pairs: Vec<_> = converter
        .fast_convert_array_to_pair_iter(&crt_in, value_count, &mut pair_scratch)
        .collect();
    let expected_pairs: Vec<_> = (0..value_count)
        .map(|i| (expected_fast_out[i], expected_fast_out[value_count + i]))
        .collect();
    assert_eq!(pairs, expected_pairs);

    // Keep exact conversion to small canonical values here. Wider edge coverage
    // belongs with an algorithm review because the current implementation uses
    // a floating correction term with parameter-sensitive behavior.
    let exact_output_base = rns_base(&[37]);
    let exact_converter = BaseConverter::new(&input_base, &exact_output_base);
    let exact_residues_by_value: Vec<_> = [0, 1, 2, 7, 16]
        .into_iter()
        .map(|value| vec![value; input_base.moduli_count()])
        .collect();
    let exact_value_count = exact_residues_by_value.len();
    let exact_crt_in = pack_modulus_major(&exact_residues_by_value, input_base.moduli_count());
    let mut exact_out = vec![ValueT::MAX; exact_value_count];
    exact_converter.exact_convert_array(&exact_crt_in, &mut exact_out, exact_value_count);

    let expected_exact: Vec<_> = exact_residues_by_value
        .iter()
        .map(|residues| residues[0] % exact_output_base.moduli()[0].value())
        .collect();
    assert_eq!(exact_out, expected_exact);
}
