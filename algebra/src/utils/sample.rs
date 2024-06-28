use num_traits::NumCast;
use rand::{CryptoRng, Rng};

use crate::Field;

/// Sample a binary vector whose values are [`Field`] `F`.
pub fn sample_binary_field_vec<F, R>(length: usize, rng: &mut R) -> Vec<F>
where
    F: Field,
    R: Rng + CryptoRng,
{
    let s = [F::zero(), F::one()];
    let mut v = vec![F::zero(); length];
    let mut iter = v.chunks_exact_mut(32);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b1) as usize];
            r >>= 1;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = s[(r & 0b1) as usize];
        r >>= 1;
    }
    v
}

/// Sample a ternary vector whose values are [`Field`] `F`.
pub fn sample_ternary_field_vec<F, R>(length: usize, rng: &mut R) -> Vec<F>
where
    F: Field,
    R: Rng + CryptoRng,
{
    let s = [F::zero(), F::zero(), F::one(), F::neg_one()];
    let mut v = vec![F::zero(); length];
    let mut iter = v.chunks_exact_mut(16);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = s[(r & 0b11) as usize];
            r >>= 2;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = s[(r & 0b11) as usize];
        r >>= 2;
    }
    v
}

/// Sample a centered binomial distribution vector whose values are [`Field`] `F`.
pub fn sample_cbd_field_vec<F, R>(length: usize, rng: &mut R) -> Vec<F>
where
    F: Field,
    R: Rng + CryptoRng,
{
    let modulus = F::MODULUS_VALUE;
    let mut cbd = || {
        let mut x: [u8; 6] = [0; 6];
        rng.fill_bytes(&mut x);
        x[2] &= 0x1F;
        x[5] &= 0x1F;
        let a = x[0].count_ones() + x[1].count_ones() + x[2].count_ones();
        let b = x[3].count_ones() + x[4].count_ones() + x[5].count_ones();
        if a >= b {
            F::new(NumCast::from(a - b).unwrap())
        } else {
            F::new(modulus - NumCast::from(b - a).unwrap())
        }
    };

    (0..length).map(|_| cbd()).collect()
}
