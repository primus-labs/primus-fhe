#![cfg(feature = "high_precision")]

use std::convert::Infallible;

use primus_distr::{PreciseCDTSampler, SignedPreciseCDTSampler};
use rand::{TryRng, distr::Distribution};

struct FixedWords([u64; 4]);

impl TryRng for FixedWords {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        panic!("expected a 256-bit draw")
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        panic!("expected a 256-bit draw")
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Infallible> {
        assert_eq!(output.len(), 32);
        for (chunk, word) in output.as_chunks_mut::<8>().0.iter_mut().zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }
}

/// External high-precision thresholds test both adapters at adjacent 256-bit words and sign boundaries.
#[test]
fn precise_adapters_follow_independent_thresholds_and_signs() {
    // sigma=1, tail=2: masses are [1/2, exp(-1/2), exp(-2)].
    // These little-endian thresholds were computed independently using Python
    // Decimal at 200 decimal digits: round_half_even(2**256 * cumulative / sum).
    // The low limbs are even, so +/-1 also exercises both sign encodings.
    let thresholds = [
        [
            0xe9f5_1a76_2554_4c58,
            0xa41d_797e_a085_3a0e,
            0x6403_b170_6823_c6a0,
            0x6712_19d0_a0c7_db01,
        ],
        [
            0x6904_93b5_ea80_bd98,
            0x92a1_ccce_79ed_7fb1,
            0x2845_8e3d_01ca_b237,
            0xe41a_0f23_b6e5_f1e1,
        ],
    ];
    let signed = SignedPreciseCDTSampler::<i64>::new(1.0, 2.0).unwrap();
    let modular = PreciseCDTSampler::<u64>::new(1.0, 2.0, 96).unwrap();
    let mut cases = vec![([0; 4], 0), ([u64::MAX; 4], 2)];
    for (i, bound) in thresholds.into_iter().enumerate() {
        let mut below = bound;
        below[0] -= 1;
        let mut above = bound;
        above[0] += 1;
        cases.extend([
            (below, i as i64),
            (bound, -(i as i64 + 1)),
            (above, i as i64 + 1),
        ]);
    }
    // Largest negative sample, immediately below the positive terminal word.
    cases.push(([u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX], -2));
    for (words, expected) in cases {
        assert_eq!(signed.sample(&mut FixedWords(words)), expected);
        assert_eq!(
            modular.sample(&mut FixedWords(words)),
            expected.rem_euclid(97) as u64
        );
    }
}
