mod extract;
mod multiple_message;
mod single_message;

pub use multiple_message::{MultiMsgLwe, MultiMsgLweIter, MultiMsgLweIterMut};
pub use single_message::{Lwe, LweIter, LweIterMut};

/// TFHE torus LWE ciphertext (coefficient domain).
///
/// Layout: `[a_1, ..., a_k, b]` — `k` mask elements + 1 body element.
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusLwe<S> = Lwe<S>;
