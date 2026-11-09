use primus_factor::ShoupFactor;
use primus_integer::{BigUint, FheUint};
use primus_modulus::BarrettModulus;
use primus_rns::{RNSBase, ResidueFactors, Residues, RnsError};

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    Base::new(&moduli).unwrap()
}

#[test]
fn construction_rejects_invalid_bases() {
    assert!(matches!(Base::new(&[]), Err(RnsError::EmptyBase)));

    let non_coprime = [21, 35].map(Modulus::new);
    assert!(matches!(
        Base::new(&non_coprime),
        Err(RnsError::NonCoprimeModuli)
    ));
}

#[test]
fn clones_share_ordered_precomputation() {
    for values in [&[97][..], &[97, 101, 103]] {
        let original = base(values);
        let clone = original.clone();
        assert_eq!(clone.moduli_values(), values);
        // Sharing is part of the base's resource contract, including the
        // contiguous numeric cache consumed by samplers and codecs.
        assert!(std::ptr::eq(original.moduli(), clone.moduli()));
        assert!(std::ptr::eq(
            original.moduli_values(),
            clone.moduli_values()
        ));
        assert!(std::ptr::eq(
            original.moduli_product().0,
            clone.moduli_product().0,
        ));
    }
}

#[test]
fn scalar_crt_matches_known_representatives() {
    let singleton = base(&[3]);
    assert_eq!(singleton.moduli_product().digits(), &[3]);
    let value = singleton.compose(Residues(&[2]));
    assert_eq!(value.digits(), &[2]);
    assert_eq!(singleton.decompose(value.view()).as_ref(), [2]);

    let base = base(&[3, 5, 7]);
    assert_eq!(base.moduli_product().digits(), &[105]);
    let value = base.compose(Residues(&[2, 4, 6]));
    assert_eq!(value.digits(), &[104]);
    assert_eq!(base.decompose(value.view()).as_ref(), [2, 4, 6]);
    let mut storage = [Value::MAX; 3];
    let mut output = Residues::new(storage.as_mut_slice());
    base.decompose_to(value.view(), output.view_mut());
    let mut reconstructed = BigUint(vec![Value::MAX; base.big_uint_value_len()]);
    base.compose_to(output.view(), reconstructed.view_mut());
    assert_eq!(reconstructed, value);
    assert_eq!(output.as_ref(), [2, 4, 6]);

    // Scalar reduction accepts more limbs than Q; only batched integers have
    // the fixed Q-width contract. Here the independent input is 2^128.
    let wide_value = BigUint(&[0, 0, 1][..]);
    assert_eq!(base.decompose(wide_value).as_ref(), [1, 1, 4]);
    base.decompose_to(wide_value, output.view_mut());
    assert_eq!(output.as_ref(), [1, 1, 4]);
}

#[test]
fn compose_and_decompose_preserve_the_modulus_major_layout() {
    let base = base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    // Q spans two u64 limbs. Form both layouts directly in u128 so a
    // matching compose/decompose bug cannot hide behind a round-trip.
    let q = base
        .moduli()
        .iter()
        .map(|m| u128::from(m.value()))
        .product::<u128>();
    let representatives = [0, 1, (1u128 << 64) - 1, 1u128 << 64, q - 1];
    let expected: Vec<_> = base
        .moduli()
        .iter()
        .flat_map(|modulus| {
            representatives
                .iter()
                .map(move |value| (value % u128::from(modulus.value())) as u64)
        })
        .collect();
    let value_len = base.big_uint_value_len();
    assert_eq!(value_len, 2);
    let values: Vec<_> = representatives
        .iter()
        .flat_map(|&value| [value as u64, (value >> 64) as u64])
        .collect();

    let mut decomposed = vec![Value::MAX; expected.len()];
    base.decompose_big_uint_values_to(&values, &mut decomposed, representatives.len());
    assert_eq!(decomposed, expected);

    let mut recomposed = vec![Value::MAX; values.len()];
    let mut scratch = vec![0; base.moduli_count()];
    base.compose_big_uint_values_to(
        &expected,
        &mut recomposed,
        representatives.len(),
        &mut scratch,
    );
    assert_eq!(recomposed, values);
}

#[test]
fn wrapping_and_scaled_decomposition_follow_the_centered_rule() {
    check_small_decomposition::<u32>();
    check_small_decomposition::<u64>();
}

// The two word widths use different SIMD lanes. The integer oracle is shared,
// while both scalar entry points and the modulus-major batch paths are checked.
fn check_small_decomposition<T: FheUint>() {
    let moduli = [97, 101, 103].map(|value| BarrettModulus::new(T::try_from(value).unwrap()));
    let base = RNSBase::new(&moduli).unwrap();
    let factor_values = [3, 5, 7];
    let factors = ResidueFactors(
        factor_values
            .iter()
            .zip(base.moduli())
            .map(|(&factor, modulus)| {
                ShoupFactor::new(T::try_from(factor).unwrap(), modulus.value())
            })
            .collect::<Vec<_>>(),
    );

    let cases: [(usize, &[usize]); 3] =
        [(2, &[0, 1]), (7, &[0, 1, 3, 4, 6]), (8, &[0, 1, 3, 4, 7])];
    for (small_modulus, values) in cases {
        // An odd length covers full SIMD lanes and the scalar tail.
        let values: Vec<_> = values.iter().copied().cycle().take(65).collect();
        let input: Vec<_> = values.iter().map(|&v| T::try_from(v).unwrap()).collect();
        let small_modulus_t = T::try_from(small_modulus).unwrap();
        // Compute the centered integer in signed arithmetic, independently
        // of the production lifting and modular-multiplication kernels.
        let centered = |value: usize| {
            if small_modulus == 2 || value < small_modulus.div_ceil(2) {
                value as isize
            } else {
                value as isize - small_modulus as isize
            }
        };

        let initial = T::try_from(11).unwrap();
        let mut decomposed = vec![T::MAX; base.moduli_count() * values.len()];
        base.wrapping_decompose_small_values_to(&input, &mut decomposed, small_modulus_t);
        let mut accumulated = vec![initial; decomposed.len()];
        base.add_wrapping_decompose_small_values_scaled_assign(
            &input,
            &mut accumulated,
            small_modulus_t,
            factors.view(),
        );

        let mut unsigned_acc = vec![initial; decomposed.len()];
        for _ in 0..2 {
            base.add_decompose_small_values_scaled_assign(
                &input,
                &mut unsigned_acc,
                factors.view(),
            );
        }
        let mut scalar_storage = vec![T::MAX; base.moduli_count()];
        for (value_index, (&value, &input_value)) in values.iter().zip(&input).enumerate() {
            let scalar = base.wrapping_decompose(input_value, small_modulus_t);
            base.wrapping_decompose_to(
                input_value,
                Residues(scalar_storage.as_mut_slice()),
                small_modulus_t,
            );
            for (modulus_index, modulus) in base.moduli().iter().enumerate() {
                let modulus: usize = modulus.value().try_into().unwrap();
                let expected = centered(value).rem_euclid(modulus as isize) as usize;
                let index = modulus_index * values.len() + value_index;
                assert_eq!(
                    scalar.as_ref()[modulus_index],
                    T::try_from(expected).unwrap()
                );
                assert_eq!(
                    scalar_storage[modulus_index],
                    T::try_from(expected).unwrap()
                );
                assert_eq!(decomposed[index], T::try_from(expected).unwrap());
                assert_eq!(
                    accumulated[index],
                    T::try_from((11 + factor_values[modulus_index] * expected) % modulus).unwrap()
                );
                assert_eq!(
                    unsigned_acc[index],
                    T::try_from((11 + 2 * factor_values[modulus_index] * value) % modulus).unwrap()
                );
            }
        }
    }
}

#[test]
fn empty_batches_preserve_scratch_and_enforce_shapes() {
    let base = base(&[97, 101, 103]);
    let factors = base.decompose_factors::<ShoupFactor<Value>>(BigUint(&[3][..]));
    let mut scratch = [11; 3];
    base.compose_big_uint_values_to(&[], &mut [], 0, &mut scratch);
    assert_eq!(scratch, [11; 3]);
    base.decompose_big_uint_values_to(&[], &mut [], 0);
    for small_modulus in [2, 7] {
        base.wrapping_decompose_small_values_to(&[], &mut [], small_modulus);
        base.add_wrapping_decompose_small_values_scaled_assign(
            &[],
            &mut [],
            small_modulus,
            factors.view(),
        );
    }
    base.add_decompose_small_values_scaled_assign(&[], &mut [], factors.view());

    // Empty input still requires empty output and the full factor vector.
    assert!(
        std::panic::catch_unwind(|| {
            base.wrapping_decompose_small_values_to(&[], &mut [0], 7);
        })
        .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| {
            base.add_decompose_small_values_scaled_assign::<ShoupFactor<Value>>(
                &[],
                &mut [],
                ResidueFactors(&[]),
            );
        })
        .is_err()
    );
}

#[test]
fn extending_a_base_matches_fresh_construction() {
    // Extension must rebuild CRT precomputations when the product gains limbs.
    // Singleton extension and whole-base extension take different paths.
    let assert_equivalent = |extended: &Base, direct: &Base, residues: &[Value]| {
        assert_eq!(extended.moduli_values(), direct.moduli_values());
        assert_eq!(extended.moduli_product(), direct.moduli_product());
        assert_eq!(
            extended.compose(Residues(residues)),
            direct.compose(Residues(residues))
        );
    };

    let q = base(&[17]);
    let extended = q.extend(Modulus::new(19)).unwrap();
    let direct = base(&[17, 19]);
    assert_equivalent(&extended, &direct, &[1, 2]);

    let q = base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    let p = base(&[1_125_899_906_031_617, 1_125_899_906_588_673]);

    let extended = q.extend(p.moduli()[0]).unwrap();
    let direct = base(&[
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
    ]);
    assert_equivalent(&extended, &direct, &[1, 2, 3]);

    let extended = q.extend_with(&p).unwrap();
    let direct = base(&[
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
        1_125_899_906_588_673,
    ]);
    assert_equivalent(&extended, &direct, &[1, 2, 3, 4]);
}
