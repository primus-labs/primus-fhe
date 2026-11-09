//! Numerical representation of native Fourier evaluation material.
/// Ordinary Fourier arithmetic or two separately rounded coefficient limbs.
/// Split is an experimental precision choice, not a certified failure probability.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FourierPrecision {
    /// Existing direct Fourier key generation and arithmetic.
    #[default]
    Ordinary,
    /// Exact native coefficient key generation, then low/high Fourier limbs.
    /// Valid only for native u64; 0 < low_bits < 64. High rounding errors are
    /// amplified by 2^low_bits. Each operation needs an independent error budget.
    Split {
        /// Number of bits in the low unsigned coefficient limb.
        low_bits: u32,
    },
}
