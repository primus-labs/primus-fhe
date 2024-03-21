use crate::Field;

/// Sample a binary vector whose values are [`Field`] `F`.
pub fn sample_binary_field_vec<F, R>(length: usize, rng: &mut R) -> Vec<F>
where
    F: Field,
    R: rand::Rng + rand::CryptoRng,
{
    let mut v = vec![F::ZERO; length];
    let mut iter = v.chunks_exact_mut(32);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            if r & 0b1 == 1 {
                *elem = F::ONE;
            }
            r >>= 1;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        if r & 0b1 == 1 {
            *elem = F::ONE;
        }
        r >>= 1;
    }
    v
}

/// Sample a ternary vector whose values are [`Field`] `F`.
pub fn sample_ternary_field_vec<F, R>(length: usize, rng: &mut R) -> Vec<F>
where
    F: Field,
    R: rand::Rng + rand::CryptoRng,
{
    let s = [F::ZERO, F::ZERO, F::ONE, F::NEG_ONE];
    let mut v = vec![F::ZERO; length];
    let mut iter = v.chunks_exact_mut(16);
    for chunk in &mut iter {
        let mut r = rng.next_u32();
        for elem in chunk.iter_mut() {
            *elem = unsafe { *s.get_unchecked((r & 0b11) as usize) };
            r >>= 2;
        }
    }
    let mut r = rng.next_u32();
    for elem in iter.into_remainder() {
        *elem = unsafe { *s.get_unchecked((r & 0b11) as usize) };
        r >>= 2;
    }
    v
}
