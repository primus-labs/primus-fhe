mod coeff;
mod extract;
#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

pub use coeff::{Ntru, NtruIter, NtruIterMut};
#[cfg(feature = "fourier")]
pub use fourier::{
    FourierNtru, FourierNtruIter, FourierNtruIterMut, FourierNtruOwned,
    FourierNtruSplitAutomorphism, FourierNtruSplitGadget,
};
#[cfg(feature = "ntt")]
pub use ntt::{NttNtru, NttNtruIter, NttNtruIterMut};

#[cfg(feature = "fourier")]
pub(crate) use fourier::accumulate_fourier_gadget_product;
#[cfg(feature = "ntt")]
pub(crate) use ntt::{accumulate_ntt_gadget_prepermuted_sum, accumulate_ntt_gadget_product};
