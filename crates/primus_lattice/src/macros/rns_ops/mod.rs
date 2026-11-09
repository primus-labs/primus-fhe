//! Component-wise arithmetic over ordered RNS moduli.

#[cfg(feature = "rns")]
#[macro_use]
mod add_sub;
#[cfg(feature = "rns")]
#[macro_use]
mod neg;
#[cfg(feature = "rns")]
#[macro_use]
mod scalar;
#[cfg(feature = "rns")]
#[macro_use]
mod factor;
