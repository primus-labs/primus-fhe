//! Batch sampling helpers grouped by logical distribution and CRT layout.

use rand::{
    distr::{Distribution, Uniform},
    seq::SliceRandom,
};

mod binary;
mod crt;
mod gaussian;
mod ternary;
mod uniform;

pub use binary::*;
pub use crt::*;
pub use gaussian::*;
pub use ternary::*;
pub use uniform::*;

/// Extends a uniformly shuffled prefix by `count` copies of `value`.
/// Moving a uniformly selected old element to the new last position and putting
/// the new value in its place preserves the uniform multiset permutation.
/// The prefix must already have the required distribution and the extension
/// must fit in `output`.
fn insert_random_values<T: Copy, R: rand::Rng + rand::CryptoRng>(
    output: &mut [T],
    prefix_length: usize,
    count: usize,
    value: T,
    rng: &mut R,
) {
    let end = prefix_length + count;
    // For dense insertions, rand batches the changing-range draws. Shuffle
    // only the new suffix into the existing uniform prefix; shuffling that
    // prefix again would do redundant work.
    if count > end / 4 {
        output[prefix_length..end].fill(value);
        let _ = output[..end].partial_shuffle(rng, count);
        return;
    }
    for index in prefix_length..end {
        let selected = Uniform::new_inclusive(0, index)
            .expect("nonempty insertion range")
            .sample(rng);
        output[index] = output[selected];
        output[selected] = value;
    }
}
