use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NtruParameters, SecretKeyDistr};
use primus_ntt::{NttTable, UintNttTable};
use primus_shape::PolyLength;

pub(super) const N: usize = 64;
pub(super) const LENGTH: PolyLength = PolyLength::new(N);
pub(super) const P: u32 = 16;
pub(super) const Q: u32 = 132_120_577;

pub(super) fn ntt_parameters(
    distribution: SecretKeyDistr,
) -> (NtruParameters<u32, BarrettModulus<u32>>, UintNttTable<u32>) {
    let modulus = BarrettModulus::new(Q);
    let parameters = NtruParameters::new(LENGTH, P, modulus, distribution, 0.7);
    (parameters, UintNttTable::new(LENGTH, modulus).unwrap())
}

pub(super) fn native_parameters(
    distribution: SecretKeyDistr,
) -> NtruParameters<u32, NativeModulus<u32>> {
    NtruParameters::new(LENGTH, P, NativeModulus::new(), distribution, 0.7)
}
