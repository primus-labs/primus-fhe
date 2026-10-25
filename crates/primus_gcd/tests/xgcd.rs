use std::{any::type_name, fmt::Debug};

use dashu_int::UBig;
use primus_gcd::Xgcd;
use rand::{RngExt, SeedableRng, rngs::StdRng};

const RANDOM_CASES: usize = 128;

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Use an independent arbitrary-precision implementation, with the zero convention adapted below.
fn big_gcd<T>(x: T, y: T) -> UBig
where
    UBig: From<T>,
{
    let x = UBig::from(x);
    let y = UBig::from(y);

    // Primus follows Rust's integer convention `gcd(0, 0) = 0`, whereas
    // dashu rejects this otherwise undefined case.
    if x == UBig::ZERO && y == UBig::ZERO {
        UBig::ZERO
    } else {
        dashu_int::ops::Gcd::gcd(x, y)
    }
}

/// Verifies the complete `u8` input space for GCD, coprimality, and the
/// extended-GCD Bézout identity.
#[test]
fn u8_gcd_and_xgcd_are_exhaustive() {
    for x in u8::MIN..=u8::MAX {
        for y in u8::MIN..=x {
            let expected_gcd = x.gcd(y);
            let (a, b, gcd) = u8::xgcd(x, y);

            assert_eq!(expected_gcd, y.gcd(x), "x={x}, y={y}");
            assert_eq!(gcd, expected_gcd, "x={x}, y={y}, a={a}, b={b}");
            assert_eq!(x.is_coprime(y), gcd == 1, "x={x}, y={y}");
            assert_eq!(
                a as u16 * x as u16 - b as u16 * y as u16,
                gcd as u16,
                "x={x}, y={y}, a={a}, b={b}, gcd={gcd}",
            );
        }
    }
}

/// Verifies the complete valid `u8` input space for the `gcdinv` range and
/// modular identity contracts.
#[test]
fn u8_gcdinv_is_exhaustive() {
    for modulus in 1..=u8::MAX {
        for value in u8::MIN..modulus {
            let (inverse, gcd) = u8::gcdinv(value, modulus);

            assert_eq!(gcd, value.gcd(modulus), "value={value}, modulus={modulus}");
            assert!(inverse < modulus, "inverse={inverse}, modulus={modulus}");
            assert_eq!(
                (inverse as u16 * value as u16) % modulus as u16,
                gcd as u16 % modulus as u16,
                "value={value}, modulus={modulus}, inverse={inverse}, gcd={gcd}",
            );
        }
    }
}

/// Verifies every odd `u8` for every supported power-of-two mask and for the
/// native-word inverse operation.
#[test]
fn u8_power_of_two_inverses_are_exhaustive() {
    for value in (1..=u8::MAX).step_by(2) {
        for bits in 1..=u8::BITS {
            let mask = if bits == u8::BITS {
                u8::MAX
            } else {
                (1u8 << bits) - 1
            };
            let inverse = u8::gcdinv_pow_of_2(value, mask).unwrap();
            assert_eq!(
                inverse.wrapping_mul(value) & mask,
                1,
                "value={value}, bits={bits}, inverse={inverse}",
            );
        }

        let inverse = u8::gcdinv_native(value).unwrap();
        assert_eq!(inverse.wrapping_mul(value), 1, "value={value}");
    }
}

fn assert_xgcd_identity<T>(x: T, y: T)
where
    T: Xgcd + Copy + Debug + Ord,
    UBig: From<T>,
{
    let (a, b, gcd) = T::xgcd(x, y);
    let ty = type_name::<T>();
    let expected_gcd = big_gcd(x, y);

    assert_eq!(
        UBig::from(x.gcd(y)),
        expected_gcd,
        "type={ty}, x={x:?}, y={y:?}",
    );
    assert_eq!(
        UBig::from(gcd),
        expected_gcd,
        "type={ty}, x={x:?}, y={y:?}, a={a:?}, b={b:?}",
    );
    assert_eq!(
        UBig::from(a) * UBig::from(x),
        UBig::from(b) * UBig::from(y) + UBig::from(gcd),
        "type={ty}, x={x:?}, y={y:?}, a={a:?}, b={b:?}, gcd={gcd:?}",
    );
}

fn assert_gcdinv_identity<T>(value: T, modulus: T)
where
    T: Xgcd + Copy + Debug + Ord,
    UBig: From<T>,
{
    let (inverse, gcd) = T::gcdinv(value, modulus);
    let ty = type_name::<T>();
    let expected_gcd = big_gcd(value, modulus);

    assert_eq!(
        UBig::from(value.gcd(modulus)),
        expected_gcd,
        "type={ty}, value={value:?}, modulus={modulus:?}",
    );
    assert_eq!(
        UBig::from(gcd),
        expected_gcd,
        "type={ty}, value={value:?}, modulus={modulus:?}, inverse={inverse:?}",
    );
    assert!(inverse < modulus);

    let big_modulus = UBig::from(modulus);
    assert_eq!(
        (UBig::from(inverse) * UBig::from(value)) % &big_modulus,
        UBig::from(gcd) % &big_modulus,
        "type={ty}, value={value:?}, modulus={modulus:?}, inverse={inverse:?}, gcd={gcd:?}",
    );
}

macro_rules! check_integer_identities {
    ($rng:ident, $ty:ty) => {
        for _ in 0..RANDOM_CASES {
            let x = $rng.random::<u128>() as $ty;
            let y: $ty = $rng.random_range(0..=x);
            assert_xgcd_identity(x, y);

            let modulus: $ty = $rng.random_range(1..=<$ty>::MAX);
            let value: $ty = $rng.random_range(0..modulus);
            assert_gcdinv_identity(value, modulus);
        }
    };
}

/// Verifies randomized GCD and modular-inverse identities for every wider
/// primitive unsigned integer type against an arbitrary-precision oracle.
#[test]
fn integer_identities_match_big_integer_oracles() {
    let mut rng = seeded_rng(0x7769_6465_5f69_6465);

    check_integer_identities!(rng, u16);
    check_integer_identities!(rng, u32);
    check_integer_identities!(rng, u64);
    check_integer_identities!(rng, u128);
    check_integer_identities!(rng, usize);
}

macro_rules! check_power_of_two_inverse {
    ($rng:ident, $ty:ty) => {
        for _ in 0..RANDOM_CASES {
            let value: $ty = ($rng.random::<u128>() as $ty) | 1;
            let bits = $rng.random_range(1..=<$ty>::BITS);
            let mask = if bits == <$ty>::BITS {
                <$ty>::MAX
            } else {
                ((1 as $ty) << bits) - 1
            };

            let inverse = <$ty>::gcdinv_pow_of_2(value, mask).unwrap();
            assert_eq!(
                inverse.wrapping_mul(value) & mask,
                1,
                "type={}, value={value}, bits={bits}",
                stringify!($ty),
            );

            let native_inverse = <$ty>::gcdinv_native(value).unwrap();
            assert_eq!(
                native_inverse.wrapping_mul(value),
                1,
                "type={}, value={value}",
                stringify!($ty),
            );
        }
    };
}

/// Verifies Newton lifting and mask truncation at every primitive word width;
/// `u8` is covered separately by its exhaustive test.
#[test]
fn power_of_two_inverses_cover_wider_integer_widths() {
    let mut rng = seeded_rng(0x706f_7732_5f77_6964);

    check_power_of_two_inverse!(rng, u16);
    check_power_of_two_inverse!(rng, u32);
    check_power_of_two_inverse!(rng, u64);
    check_power_of_two_inverse!(rng, u128);
    check_power_of_two_inverse!(rng, usize);
}

/// Verifies the explicitly optimized high-MSB and high-quotient `u64` paths
/// against exact arbitrary-precision identities.
#[test]
fn u64_high_bit_paths_match_big_integer_oracles() {
    let mut rng = seeded_rng(0x7536_345f_6d73_625f);
    const TOP_BIT: u64 = 1 << (u64::BITS - 1);

    for _ in 0..RANDOM_CASES {
        let x = rng.random_range(TOP_BIT..=u64::MAX);
        let y = rng.random_range(TOP_BIT..=x);
        assert_xgcd_identity(x, y);

        let modulus = rng.random_range((TOP_BIT + 1)..=u64::MAX);
        let value = rng.random_range(TOP_BIT..modulus);
        assert_gcdinv_identity(value, modulus);
    }

    let high_quotient = TOP_BIT;
    assert_eq!(u64::xgcd(high_quotient, 1), (1, high_quotient - 1, 1));
    assert_eq!(u64::gcdinv(1, high_quotient), (1, 1));
}

/// Verifies full-width `u128` identities with an arbitrary-precision integer
/// oracle independent of the implementation under test.
#[test]
fn u128_boundary_identities_match_big_integer_oracles() {
    const TOP_BIT: u128 = 1 << 127;

    for (x, y) in [
        (0, 0),
        (1, 0),
        (u128::MAX, u128::MAX),
        (u128::MAX, u128::MAX - 1),
        (u128::MAX, TOP_BIT + 1),
        (TOP_BIT, 1),
        (TOP_BIT + 123, TOP_BIT),
    ] {
        assert_xgcd_identity(x, y);
    }

    for (value, modulus) in [
        (0, 1),
        (1, 2),
        (1, TOP_BIT),
        (TOP_BIT - 1, TOP_BIT),
        (TOP_BIT, u128::MAX),
        (u128::MAX - 1, u128::MAX),
    ] {
        assert_gcdinv_identity(value, modulus);
    }
}
