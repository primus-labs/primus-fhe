use aligned_vec::AVec;
use primus_factor::{MultiplyFactor, ShoupFactor};

/// Computes a Barrett-preconditioned vector for a given bit shift.
///
/// For each `value` in `values`, computes `floor(value * 2^bit_shift / modulus)`.
pub(super) fn build_barrett_vector(values: &[u64], bit_shift: u32, modulus: u64) -> AVec<u64> {
    AVec::from_iter(
        64,
        values
            .iter()
            .map(|&value| MultiplyFactor::new(value, bit_shift, modulus).quotient()),
    )
}

/// Scalar root preconditioners at the width selected by the owning variant.
#[derive(Clone)]
pub(super) struct ScalarPrecomputation {
    pub(super) roots_precon: AVec<u64>,
    pub(super) inv_roots_precon: AVec<u64>,
}

impl ScalarPrecomputation {
    #[must_use]
    pub(super) fn new<const BITS: u32>(q: u64, roots: &[u64], inv_roots: &[u64]) -> Self {
        Self {
            roots_precon: build_root_preconditioners(roots, BITS, q),
            inv_roots_precon: build_root_preconditioners(inv_roots, BITS, q),
        }
    }
}

/// AVX2 uses scalar twiddles for broadcast stages and packed twiddles for T2/T1.
#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
pub(super) struct Avx2Precomputation {
    pub(super) scalar: ScalarPrecomputation,
    pub(super) roots: AVec<u64>,
    pub(super) roots_precon: AVec<u64>,
    pub(super) inv_roots: AVec<u64>,
    pub(super) inv_roots_precon: AVec<u64>,
}

#[cfg(target_arch = "x86_64")]
impl Avx2Precomputation {
    #[must_use]
    pub(super) fn new(q: u64, roots: &[u64], inv_roots: &[u64]) -> Self {
        use super::avx2::precompute::build_avx2_roots_u64;

        let n = roots.len();
        let scalar = ScalarPrecomputation::new::<64>(q, roots, inv_roots);
        Self {
            roots: build_avx2_roots_u64(n, roots, false),
            roots_precon: build_avx2_roots_u64(n, &scalar.roots_precon, false),
            inv_roots: build_avx2_roots_u64(n, inv_roots, true),
            inv_roots_precon: build_avx2_roots_u64(n, &scalar.inv_roots_precon, true),
            scalar,
        }
    }
}

/// AVX-512 forward roots use the HEXL T8/T4/T2/T1 layout; inverse roots
/// stay in the canonical table and need only width-specific preconditioners.
#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
pub(super) struct Avx512Precomputation {
    pub(super) roots: AVec<u64>,
    pub(super) roots_precon: AVec<u64>,
    pub(super) inv_roots_precon: AVec<u64>,
}

#[cfg(target_arch = "x86_64")]
impl Avx512Precomputation {
    #[must_use]
    pub(super) fn new<const BITS: u32>(q: u64, roots: &[u64], inv_roots: &[u64]) -> Self {
        let roots = super::avx512::precompute::build_avx512_root_powers(roots.len(), roots);
        Self {
            roots_precon: build_barrett_vector(&roots, BITS, q),
            roots,
            inv_roots_precon: build_root_preconditioners(inv_roots, BITS, q),
        }
    }
}

/// Owns exactly the precomputation used by one forward/inverse kernel pair.
/// The variants also bind its Barrett width; no unused buffers are retained.
#[derive(Clone)]
pub(super) enum U64Backend {
    Scalar32(ScalarPrecomputation),
    Scalar64(ScalarPrecomputation),
    #[cfg(target_arch = "x86_64")]
    Avx2(Avx2Precomputation),
    #[cfg(target_arch = "x86_64")]
    Avx512Dq32(Avx512Precomputation),
    #[cfg(target_arch = "x86_64")]
    Avx512Dq64(Avx512Precomputation),
    #[cfg(target_arch = "x86_64")]
    Avx512Ifma52(Avx512Precomputation),
}

impl U64Backend {
    /// Selects and prepares one kernel valid for both transform directions.
    #[must_use]
    pub(super) fn new(q: u64, roots: &[u64], inv_roots: &[u64]) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            use super::avx512::internal::{IFMA_SHIFT_BITS, MAX_DQ32_MODULUS, MAX_IFMA_MODULUS};

            // IFMA and all DQ fallbacks require AVX-512DQ. The narrow widths
            // are valid only below both directions' modulus bounds.
            let has_dq = is_x86_feature_detected!("avx512dq");
            if is_x86_feature_detected!("avx512ifma") && has_dq && q < MAX_IFMA_MODULUS {
                return Self::Avx512Ifma52(Avx512Precomputation::new::<{ IFMA_SHIFT_BITS }>(
                    q, roots, inv_roots,
                ));
            }
            if has_dq {
                return if q < MAX_DQ32_MODULUS {
                    Self::Avx512Dq32(Avx512Precomputation::new::<32>(q, roots, inv_roots))
                } else {
                    Self::Avx512Dq64(Avx512Precomputation::new::<64>(q, roots, inv_roots))
                };
            }
            if is_x86_feature_detected!("avx2") && q >= (1u64 << 30) {
                return Self::Avx2(Avx2Precomputation::new(q, roots, inv_roots));
            }
        }
        if q < (1u64 << 30) {
            Self::Scalar32(ScalarPrecomputation::new::<32>(q, roots, inv_roots))
        } else {
            Self::Scalar64(ScalarPrecomputation::new::<64>(q, roots, inv_roots))
        }
    }

    /// Barrett width for the table's fused final inverse stage.
    #[must_use]
    pub(super) fn bit_shift(&self) -> u32 {
        match self {
            Self::Scalar32(_) => 32,
            Self::Scalar64(_) => 64,
            #[cfg(target_arch = "x86_64")]
            Self::Avx2(_) | Self::Avx512Dq64(_) => 64,
            #[cfg(target_arch = "x86_64")]
            Self::Avx512Dq32(_) => 32,
            #[cfg(target_arch = "x86_64")]
            Self::Avx512Ifma52(_) => super::avx512::internal::IFMA_SHIFT_BITS,
        }
    }
}

/// Prepares canonical root twiddles with Shoup quotients at 64 bits;
/// narrower Barrett twiddles use the requested shift directly.
fn build_root_preconditioners(values: &[u64], bit_shift: u32, q: u64) -> AVec<u64> {
    if bit_shift == 64 {
        AVec::from_iter(
            64,
            values
                .iter()
                .map(|&w| ShoupFactor::<u64>::quotient_for(w, q)),
        )
    } else {
        build_barrett_vector(values, bit_shift, q)
    }
}
