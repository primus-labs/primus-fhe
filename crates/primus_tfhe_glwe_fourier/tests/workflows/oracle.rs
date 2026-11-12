use primus_fft::TorusFftValue;
use primus_modulus::NativeModulus;
use primus_reduce::{EncodeSigned, ReduceMul};

/// Independent native schoolbook phase, including negacyclic wrap signs. This
/// inspects stored key rows without using the Fourier decryption implementation.
pub(super) fn native_material_phase<T: TorusFftValue>(
    ciphertext: &[T],
    secret: &[T::SignedInteger],
    n: usize,
) -> Vec<T> {
    use primus_reduce::{ReduceAdd, ReduceSub};

    let modulus = NativeModulus::new();
    let (mask, body) = ciphertext.split_at(secret.len());
    let mut phase = body.to_vec();
    for (a, s) in primus_poly::PolynomialIter::new(mask, n).zip(secret.chunks_exact(n)) {
        for (degree, value) in phase.iter_mut().enumerate() {
            for (j, &s) in s.iter().enumerate() {
                let i = (degree + n - j) & (n - 1);
                let product = modulus.reduce_mul(a.as_ref()[i], modulus.encode_signed(s));
                *value = if i + j < n {
                    modulus.reduce_sub(*value, product)
                } else {
                    modulus.reduce_add(*value, product)
                };
            }
        }
    }
    phase
}
