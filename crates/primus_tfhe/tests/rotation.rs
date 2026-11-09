//! Quantization oracle shared by LUT compilation and all blind-rotation backends.

use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use primus_tfhe::rotation::RotationModulusSwitch;

/// Integer reference includes upward ties and wrap; it does not use ModulusSwitch.
fn check_rounding<T: FheUint, M: RingContext<T>>(modulus: M, q: u128) {
    let mut rebound = RotationModulusSwitch::new(modulus, 64, 1);
    for step in [1, 4, 2, 1] {
        let target = 64 / step;
        let samples: Vec<u128> = if q <= 256 {
            (0..q).collect()
        } else {
            // Each rounding boundary and its neighbors, plus the canonical endpoints.
            let mut values = vec![0, q - 1];
            for k in 1..=target {
                let boundary = (k * q - q / 2).div_ceil(target);
                values.extend([boundary - 1, boundary, boundary + 1]);
            }
            values
        };
        let input: Vec<T> = samples.iter().map(|&x| T::as_from(x)).collect();
        let expected: Vec<_> = samples
            .iter()
            .map(|&x| (((x * target + q / 2) / q) % target * step) as usize)
            .collect();
        let switch = RotationModulusSwitch::new(modulus, 64, step as usize);
        rebound = rebound.with_step(step as usize);
        let mut batch = vec![usize::MAX; input.len()];
        switch.exponent_slice_to(&input, &mut batch);
        assert_eq!(batch, expected);
        rebound.exponent_slice_to(&input, &mut batch);
        assert_eq!(batch, expected);
        for (&value, exponent) in input.iter().zip(expected) {
            assert_eq!(switch.exponent(value), exponent);
        }
    }
}

#[test]
fn rounding_matches_integer_oracle() {
    check_rounding(BarrettModulus::new(97u32), 97);
    check_rounding(
        BarrettModulus::new(1_125_899_906_826_241u64),
        1_125_899_906_826_241,
    );
    check_rounding(PowOf2Modulus::new(256u32), 256);
    check_rounding(NativeModulus::<u32>::new(), 1u128 << 32);
    check_rounding(NativeModulus::<u64>::new(), 1u128 << 64);
}

#[test]
fn batch_shape_error_precedes_writes() {
    let switch = RotationModulusSwitch::new(PowOf2Modulus::new(256u32), 64, 4);
    let mut output = [usize::MAX; 2];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        switch.exponent_slice_to(&[32, 64, 96], &mut output);
    }));
    assert!(result.is_err());
    assert_eq!(output, [usize::MAX; 2]);
}
