//! Configuration preparation preserves reducer-specific ranges for both FHE word widths.

use primus_integer::FheUint;
use primus_modulus::{
    BarrettModulus, ModulusConfig, ModulusConfigError, NativeModulus, PowOf2Modulus,
};
use primus_reduce::Modulus;

/// Explicit bounds differ from the implicit native torus, even for powers of two.
fn check_config_bounds<T: FheUint>() {
    let native = NativeModulus::<T>::try_from(ModulusConfig::Native).unwrap();
    assert_eq!(ModulusConfig::from(native), ModulusConfig::Native);
    assert_eq!(
        BarrettModulus::<T>::try_from(ModulusConfig::Native),
        Err(ModulusConfigError::Barrett)
    );
    assert_eq!(
        PowOf2Modulus::<T>::try_from(ModulusConfig::Native),
        Err(ModulusConfigError::PowOf2)
    );

    let barrett_limit = T::ONE << (T::BITS - 2);
    for value in [T::TWO, barrett_limit - T::ONE] {
        let modulus = BarrettModulus::<T>::try_from(ModulusConfig::Explicit(value)).unwrap();
        assert_eq!(modulus.explicit_value(), Some(value));
        assert_eq!(ModulusConfig::from(modulus), ModulusConfig::Explicit(value));
    }
    for value in [T::ZERO, T::ONE, barrett_limit, T::MAX] {
        assert_eq!(
            BarrettModulus::<T>::try_from(ModulusConfig::Explicit(value)),
            Err(ModulusConfigError::Barrett)
        );
    }

    for value in [T::TWO, T::ONE << (T::BITS - 1)] {
        let modulus = PowOf2Modulus::<T>::try_from(ModulusConfig::Explicit(value)).unwrap();
        assert_eq!(modulus.explicit_value(), Some(value));
        assert_eq!(ModulusConfig::from(modulus), ModulusConfig::Explicit(value));
    }
    for value in [T::ZERO, T::ONE, T::TWO + T::ONE, T::MAX] {
        assert_eq!(
            PowOf2Modulus::<T>::try_from(ModulusConfig::Explicit(value)),
            Err(ModulusConfigError::PowOf2)
        );
    }

    // No representable explicit value denotes the native full-width modulus.
    for value in [T::ZERO, T::ONE, T::TWO, T::MAX] {
        assert_eq!(
            NativeModulus::<T>::try_from(ModulusConfig::Explicit(value)),
            Err(ModulusConfigError::Native)
        );
    }
}

#[test]
fn config_bounds_u32() {
    check_config_bounds::<u32>();
}

#[test]
fn config_bounds_u64() {
    check_config_bounds::<u64>();
}
