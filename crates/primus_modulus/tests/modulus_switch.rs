//! Fixed-pair switching checked with independent u128 integer arithmetic.
use primus_modulus::integer::FheUint;
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::{Modulus, ModulusSwitch, PrepareModulusSwitch};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn value<T: TryFrom<u128>>(x: u128) -> T {
    T::try_from(x).ok().unwrap()
}

/// Exhaust tiny domains; larger domains retain endpoints and the central rounding neighborhood.
fn points(end: u128) -> Vec<u128> {
    if end <= 256 {
        (0..end).collect()
    } else {
        vec![0, 1, end / 2 - 1, end / 2, end / 2 + 1, end - 2, end - 1]
    }
}

/// Use an exact u128 rounding formula, including transition neighbors and fixed interior samples.
fn check_pair<T, S, D>(source: S, target: D)
where
    T: FheUint + Into<u128> + TryFrom<u128>,
    S: PrepareModulusSwitch<ValueT = T>,
    D: Modulus<ValueT = T>,
{
    let native = 1u128 << T::BITS;
    let q = source.explicit_value().map(Into::into).unwrap_or(native);
    let r = target.explicit_value().map(Into::into).unwrap_or(native);
    // Exercise both construction routes: source-specific reciprocal reuse and
    // generic construction must obey the same rounding and payload contract.
    let conversions = [
        source.prepare_switch_to(target),
        ModulusSwitch::new(source, target),
    ];
    let mut inputs = points(q);
    let mut rng = StdRng::seed_from_u64((q ^ r) as u64);
    inputs.extend((0..32).map(|_| rng.random_range(0..q)));
    for m in [0, r / 2, r - 1] {
        // Equivalent to ceil(((m+1)*q-floor(q/2))/r), avoiding 2^128.
        let boundary = (m * q + q.div_ceil(2)).div_ceil(r);
        if boundary > 0 && boundary < q {
            inputs.extend([boundary - 1, boundary]);
        }
    }
    let expected: Vec<T> = inputs
        .iter()
        .map(|&x| value(((x * r + q / 2) / q) % r))
        .collect();
    for conversion in conversions {
        for (&x, &expected) in inputs.iter().zip(&expected) {
            assert_eq!(
                conversion.switch(value(x)),
                expected,
                "source={q}, target={r}, value={x}"
            );
        }
        // The batch path must preserve payloads while using the same rounding.
        let mut actual = vec![T::ZERO; inputs.len()];
        conversion.switch_map(
            inputs
                .iter()
                .copied()
                .enumerate()
                .map(|(i, x)| (value(x), i)),
            |x, i| actual[i] = x,
        );
        assert_eq!(actual, expected);
    }
}

/// Bind each source representation to representative target kinds, including native output.
/// Numeric kernel selection is covered separately; wrapper pairs need no Cartesian grid.
fn check_source<T, S>(source: S)
where
    T: FheUint + Into<u128> + TryFrom<u128>,
    S: PrepareModulusSwitch<ValueT = T>,
{
    check_pair(source, NativeModulus::<T>::new());
    check_pair(source, UintModulus::<T>::new(value(2)));
    check_pair(
        source,
        UintModulus::<T>::new(value((1u128 << T::BITS) / 2 + 1)),
    );
    check_pair(source, PowOf2Modulus::<T>::new(value(128)));
    check_pair(source, CompactModulus::<T>::new(value(131)));
    check_pair(source, BarrettModulus::<T>::new(value(131)));
}

/// Ratios select distinct kernels; word widths retain overflow and native-modulus boundaries.
#[test]
fn fixed_pairs_match_integer_oracle() {
    fn cases<T: FheUint + Into<u128> + TryFrom<u128>>() {
        let native = 1u128 << T::BITS;
        let compact = native / 4 - 3;
        for (q, r) in [
            (97, 97), // Identity.
            // Binary down/up shifts.
            (128, 16),
            (16, 128),
            // Exact expansion: multiply / shift.
            (9, 27),
            (9, 36),
            // Exact contraction: divide / shift.
            (45, 9),
            (36, 9),
            // Expansion with a narrow remainder product.
            (97, 257),
            // Binary source, nonbinary target in both directions.
            (128, 97),
            (128, 257),
            // Compact source: narrow and wide biased numerators.
            (97, 9),
            (compact, compact - 2),
            // Noncompact source: one-word and two-word products.
            (native / 4 + 1, 2),
            (native - 1, native / 2 + 1),
        ] {
            check_pair(
                UintModulus::<T>::new(value(q)),
                UintModulus::<T>::new(value(r)),
            );
        }
        let native_modulus = NativeModulus::<T>::new();
        check_pair(native_modulus, native_modulus);
        check_pair(native_modulus, PowOf2Modulus::<T>::new(value(128)));
        check_pair(native_modulus, UintModulus::<T>::new(value(97)));
        // Native targets distinguish exact widening, remainder decomposition,
        // compact reciprocal division, and general two-word division.
        for q in [128, 3, compact, native / 2 + 1] {
            check_pair(UintModulus::<T>::new(value(q)), native_modulus);
        }
        check_source(PowOf2Modulus::<T>::new(value(128)));
        check_source(CompactModulus::<T>::new(value(compact)));
        check_source(BarrettModulus::<T>::new(value(compact)));
    }
    cases::<u16>();
    cases::<u32>();
    cases::<u64>();
}

/// Exhaust residues near reciprocal-division bounds to detect quotient-correction errors.
#[test]
fn compact_quotients_exhaust_small_word_residues() {
    // Near the compact limit, wide products and quotient corrections are common.
    for q in [257u16, 16381, 16383] {
        let source = BarrettModulus::new(q);
        for p in [2u32, 131, 32769, 65535, 65536] {
            let conversion = if p == 65536 {
                source.prepare_switch_to(NativeModulus::new())
            } else {
                source.prepare_switch_to(UintModulus::new(p as u16))
            };
            conversion.switch_map((0..q).map(|x| (x, x)), |y, i| {
                let expected =
                    ((i as u64 * u64::from(p) + u64::from(q / 2)) / u64::from(q)) % u64::from(p);
                assert_eq!(u64::from(y), expected, "q={q}, p={p}, x={i}");
                assert_eq!(conversion.switch(i), y);
            });
        }
    }
}

/// Generated contexts must support both source preparation and target metadata.
#[cfg(feature = "derive")]
#[test]
fn derived_modulus_supports_both_directions() {
    #[derive(primus_modulus::Barrett)]
    #[modulus(ty = u32, value = 97)]
    struct Q;
    check_source::<u32, _>(Q);
    check_pair(NativeModulus::<u32>::new(), Q);
    check_pair(UintModulus::new(128u32), Q);
}
