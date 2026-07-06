mod arithmetic;
mod permute;

pub(super) use arithmetic::*;
pub(super) use permute::*;

/// Represents binary comparison operations between two boolean values.
///
/// The numeric values match the Intel immediate (`imm8`) used by
/// `_mm512_cmp_epu64_mask`:
/// 0=EQ, 1=LT, 2=LE, 3=FALSE, 4=NE, 5=NLT, 6=NLE, 7=TRUE.
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum CmpInt {
    /// Equal
    Eq = 0,
    /// Less than
    Lt = 1,
    /// Less than or equal
    Le = 2,
    /// False
    False = 3,
    /// Not equal
    Ne = 4,
    /// Not less than
    Nlt = 5,
    /// Not less than or equal
    Nle = 6,
    /// True
    True = 7,
}
