/// NOT
#[inline]
pub fn not(a: bool) -> bool {
    !a
}

/// AND
#[inline]
pub fn and(a: bool, b: bool) -> bool {
    a & b
}

/// NAND
#[inline]
pub fn nand(a: bool, b: bool) -> bool {
    not(and(a, b))
}

/// OR
#[inline]
pub fn or(a: bool, b: bool) -> bool {
    a | b
}

/// NOR
#[inline]
pub fn nor(a: bool, b: bool) -> bool {
    not(or(a, b))
}

/// XOR
#[inline]
pub fn xor(a: bool, b: bool) -> bool {
    a ^ b
}

/// XNOR
#[inline]
pub fn xnor(a: bool, b: bool) -> bool {
    not(xor(a, b))
}

/// MAJ
#[inline]
pub fn majority(a: bool, b: bool, c: bool) -> bool {
    (a & b) | (b & c) | (a & c)
}
