//! CPU feature detection — evaluated once on first access.
//!
//! All backends share these flags so that feature detection runs exactly
//! once per flag, regardless of how many backends reference it.

use std::sync::LazyLock;

/// AVX2 available on this x86_64 CPU.
#[cfg(target_arch = "x86_64")]
pub static HAS_AVX2: LazyLock<bool> = LazyLock::new(|| is_x86_feature_detected!("avx2"));

/// AVX-512 IFMA52 available on this x86_64 CPU.
#[cfg(target_arch = "x86_64")]
pub static HAS_AVX512IFMA: LazyLock<bool> =
    LazyLock::new(|| is_x86_feature_detected!("avx512ifma"));

/// AVX-512 DQ available on this x86_64 CPU.
#[cfg(target_arch = "x86_64")]
pub static HAS_AVX512DQ: LazyLock<bool> = LazyLock::new(|| is_x86_feature_detected!("avx512dq"));
