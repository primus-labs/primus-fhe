//! utility

/// NOT
#[inline]
pub const fn not(a: bool) -> bool {
    !a
}

/// AND
#[inline]
pub const fn and(a: bool, b: bool) -> bool {
    a & b
}

/// NAND
#[inline]
pub const fn nand(a: bool, b: bool) -> bool {
    not(and(a, b))
}

/// OR
#[inline]
pub const fn or(a: bool, b: bool) -> bool {
    a | b
}

/// NOR
#[inline]
pub const fn nor(a: bool, b: bool) -> bool {
    not(or(a, b))
}

/// XOR
#[inline]
pub const fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

/// XNOR
#[inline]
pub const fn xnor(a: bool, b: bool) -> bool {
    not(xor(a, b))
}

/// MAJ
#[inline]
pub const fn majority(a: bool, b: bool, c: bool) -> bool {
    (a & b) | (b & c) | (a & c)
}
