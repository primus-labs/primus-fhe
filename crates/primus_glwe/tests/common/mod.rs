//! Small exact fixtures shared by evaluation tests.

use primus_lattice::glwe::Glwe;
use rand::{RngExt, rngs::StdRng};

pub(super) const N: usize = 32;
pub(super) const K: usize = 2;

// Exact schoolbook oracle, independent of NTT/FFT and sample extraction.
fn add_secret_product(values: &mut [u64], masks: &[u64], secret: &[i64], q: u128, subtract: bool) {
    for (a, s) in masks
        .as_chunks::<N>()
        .0
        .iter()
        .zip(secret.as_chunks::<N>().0)
    {
        for (i, &a) in a.iter().enumerate() {
            for (j, &s) in s.iter().enumerate() {
                let index = (i + j) % N;
                let neg = (s < 0) ^ (i + j >= N) ^ subtract;
                let product = u128::from(a) * s.unsigned_abs() as u128 % q;
                let add = if neg { (q - product) % q } else { product };
                values[index] = ((u128::from(values[index]) + add) % q) as u64;
            }
        }
    }
}

// Construct b = m + a*s with zero noise so evaluation-key error stays identifiable.
pub(super) fn encrypt(
    message: &[u64],
    secret: &[i64],
    q: u128,
    rng: &mut StdRng,
) -> Glwe<Vec<u64>> {
    let mut output = vec![0; (K + 1) * N];
    let (mask, body) = output.split_at_mut(K * N);
    for a in mask.iter_mut() {
        *a = (u128::from(rng.random::<u64>()) % q) as u64;
    }
    body.copy_from_slice(message);
    add_secret_product(body, mask, secret, q, false);
    Glwe::new(output)
}

// Recover b - a*s using the same coefficient-ring convention as the oracle.
pub(super) fn phase(cipher: &[u64], secret: &[i64], q: u128) -> Vec<u64> {
    let (mask, body) = cipher.split_at(K * N);
    let mut output = body.to_vec();
    add_secret_product(&mut output, mask, secret, q, true);
    output
}

pub(super) fn assert_phase(cipher: &[u64], expected: &[u64], secret: &[i64], q: u128) {
    let actual = phase(cipher, secret, q);
    assert_eq!(actual.len(), expected.len());
    for (i, (&actual, &expected)) in actual.iter().zip(expected).enumerate() {
        let distance = (u128::from(actual) + q - u128::from(expected)) % q;
        assert!(
            distance.min(q - distance) < q / 4096,
            "phase[{i}]: {actual}, expected {expected}, distance {}",
            distance.min(q - distance)
        );
    }
}

pub(super) fn secret() -> Vec<i64> {
    (0..K * N)
        .map(|i| match (i * 7 + i / 3) % 3 {
            0 => -1,
            1 => 0,
            _ => 1,
        })
        .collect()
}

pub(super) fn message(q: u128) -> Vec<u64> {
    (0..N)
        .map(|i| (((3 * i + 1) % 16) as u128 * (q / 64)) as u64)
        .collect()
}
