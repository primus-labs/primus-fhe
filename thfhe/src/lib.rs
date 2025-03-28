mod parameter;

// const POLYNOMIAL_COUNT: usize = 1024;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod lwe;
mod rlwe;

mod distdec;
mod encrypt;
mod evaluate;
mod key_gen;

mod secret_key;

pub use parameter::*;

pub use distdec::*;
pub use encrypt::*;
pub use evaluate::*;
pub use key_gen::*;
pub use lwe::*;
pub use rlwe::*;

pub use secret_key::*;
