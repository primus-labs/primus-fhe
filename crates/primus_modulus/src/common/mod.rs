//! Low-level kernels shared by the concrete modulus contexts.
//!
//! Unless a function documents otherwise, callers must provide the operand
//! ranges required by the corresponding `primus_reduce` trait. Slice lengths
//! must match; most shape checks in this module are debug-only.

/// Helpers for compact moduli that rely on tighter modulus bounds.
pub mod compact;
/// Helpers for generic unsigned-integer moduli.
pub mod uint;
