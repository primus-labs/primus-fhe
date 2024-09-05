mod borrowing_sub;
mod carrying_add;
mod carrying_mul;
mod widening_mul;

pub use borrowing_sub::BorrowingSub;
pub use carrying_add::CarryingAdd;
pub use carrying_mul::CarryingMul;
pub use widening_mul::WideningMul;

/// A trait for big number calculation
pub trait Widening: CarryingAdd + BorrowingSub + WideningMul + CarryingMul {}

impl<T> Widening for T where T: CarryingAdd + BorrowingSub + WideningMul + CarryingMul {}
