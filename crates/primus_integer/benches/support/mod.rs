use rand::rngs::StdRng;
use rand::{Fill, RngExt};

pub const RNG_SEED: u64 = 0x696e_7465_6765_725f;

pub fn random_values<T>(rng: &mut StdRng, len: usize) -> Vec<T>
where
    T: Copy + Default + Fill,
{
    let mut values = vec![T::default(); len];
    rng.fill(values.as_mut_slice());
    values
}
