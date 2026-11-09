mod coeff;
mod extract;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::{Ntru, NtruIter, NtruIterMut};
#[cfg(feature = "ntt")]
pub use ntt::{NttNtru, NttNtruIter, NttNtruIterMut};

#[cfg(feature = "ntt")]
pub(crate) use ntt::{accumulate_ntt_gadget_prepermuted_sum, accumulate_ntt_gadget_product};
