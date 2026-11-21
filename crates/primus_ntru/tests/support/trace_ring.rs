use primus_integer::{AsFrom, FheUint};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_ntt::{NttTable, U64NttTable};
use primus_shape::PolyLength;

pub(super) const N: usize = 32;
pub(super) const LENGTH: PolyLength = PolyLength::new(N);
pub(super) const Q: u64 = 1_125_899_906_826_241;

pub(super) fn ntt_parameters(
    plain_modulus: u64,
) -> (NtruParameters<u64, BarrettModulus<u64>>, U64NttTable) {
    let modulus = BarrettModulus::new(Q);
    let parameters = NtruParameters::new(
        LENGTH,
        plain_modulus,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    (parameters, U64NttTable::new(LENGTH, modulus).unwrap())
}

pub(super) fn native_parameters(plain_modulus: u64) -> NtruParameters<u64, NativeModulus<u64>> {
    NtruParameters::new(
        LENGTH,
        plain_modulus,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        0.7,
    )
}

// The phase oracles use f = 1 + X - X^3.
pub(super) fn oracle_secret<T: FheUint>(length: PolyLength) -> NtruSecretKey<T> {
    let mut coefficients = vec![T::SignedInteger::as_from(0i32); length.get()];
    for (index, coefficient) in [(0, 1i32), (1, 1), (3, -1)] {
        coefficients[index] = T::SignedInteger::as_from(coefficient);
    }
    NtruSecretKey::new(coefficients, SecretKeyDistr::SparseTernary)
}
