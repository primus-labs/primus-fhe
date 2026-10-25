#[test]
fn u64_torus_conversion_preserves_round_saturate_and_wrap() {
    use primus_fft::TorusFftValue;
    check_torus_conversion::<u64>(
        |x| ((x * u64::TORUS_SCALE_INVERSE).round() as i128) as u64,
        2.0f64.powi(63),
    );
}

#[test]
fn u32_torus_conversion_preserves_round_saturate_and_wrap() {
    use primus_fft::TorusFftValue;
    check_torus_conversion::<u32>(
        |x| ((x * u32::TORUS_SCALE_INVERSE).round() as i64) as u32,
        2.0f64.powi(31),
    );
}

// Compare conversion with Rust's floating rounding and saturating
// signed cast, followed by unsigned wrapping. No FFT approximation is involved.
fn check_torus_conversion<T: primus_fft::TorusFftValue>(
    reference: impl Fn(f64) -> T,
    saturation_edge: f64,
) {
    let mut inputs = vec![
        0.0,
        -0.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MAX,
        f64::MIN,
    ];
    // Half-integers in coefficient units, fractional periods, the last f64
    // fractions before all values become integral, and signed saturation edges.
    for value in [
        0.5 * T::TORUS_SCALE,
        1.5 * T::TORUS_SCALE,
        3.5 * T::TORUS_SCALE,
        0.5,
        1.0,
        1.25,
        1.75,
        2.0,
        2.0f64.powi(52) * T::TORUS_SCALE,
        2.0f64.powi(51),
        2.0f64.powi(52),
        saturation_edge,
    ] {
        for bits in [value.to_bits() - 1, value.to_bits(), value.to_bits() + 1] {
            inputs.push(f64::from_bits(bits));
            inputs.push(-f64::from_bits(bits));
        }
    }
    // Every floating exponent with representative mantissas and both signs.
    for exponent in 0..=0x7ffu64 {
        for fraction in [0, 1, (1u64 << 51) - 1, 1u64 << 51, (1u64 << 52) - 1] {
            for sign in [0, 1u64 << 63] {
                inputs.push(f64::from_bits(sign | (exponent << 52) | fraction));
            }
        }
    }
    // Keep assertions outside the conversion loop so release tests also
    // exercise compiler vectorization, including mixed finite/NaN/Inf lanes.
    let converted: Vec<_> = inputs.iter().copied().map(T::from_torus_f64).collect();
    for (x, actual) in inputs.into_iter().zip(converted) {
        let expected = reference(x);
        assert_eq!(actual, expected, "vector input bits: {:016x}", x.to_bits());
        assert_eq!(
            T::from_torus_f64(x),
            expected,
            "scalar input bits: {:016x}",
            x.to_bits()
        );
    }
}
