/// Reverses the low `bits` of an index and clears the higher bits.
/// Internal callers establish `bits <= usize::BITS`.
#[inline]
pub(crate) fn reverse_lsbs(index: usize, bits: u32) -> usize {
    debug_assert!(bits <= usize::BITS);
    if index == 0 || bits == 0 {
        0
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}
