//! Shared numerical utilities used by Gaussian sampler implementations.

use std::cmp::Ordering;

/// Returns the magnitude selected by a CDT with an inclusive terminal sentinel.
///
/// The first entry is the lower sentinel and the last entry is the maximum
/// random word. The terminal word belongs to the final supported magnitude,
/// rather than introducing an additional magnitude past the table's support.
#[inline(always)]
pub(crate) fn cdt_index_by<T>(
    cdt: &[T],
    random: &T,
    mut compare: impl FnMut(&T, &T) -> Ordering,
) -> usize {
    debug_assert!(cdt.len() >= 2);

    let upper = cdt.partition_point(|bound| compare(bound, random).is_le());
    debug_assert!(upper > 0);

    upper.saturating_sub(1).min(cdt.len().saturating_sub(2))
}

#[cfg(test)]
mod tests {
    use super::cdt_index_by;

    /// The maximum random word must not select a magnitude beyond the truncated support.
    #[test]
    fn terminal_sentinel_maps_to_last_supported_index() {
        let cdt = [0_u8, 2, 5, u8::MAX];

        assert_eq!(cdt_index_by(&cdt, &u8::MAX, Ord::cmp), cdt.len() - 2);
    }
}
