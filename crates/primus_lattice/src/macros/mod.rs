//! Ciphertext implementation macros.
//!
//! Pass type names without storage generics: `impl_common!(Lwe)`.
//! At each type declaration, group invocations in this order:
//! storage/construction, iteration/access, arithmetic, domain conversion.
//! Both directions of a conversion are generated in its transform module
//! (`ntt`, `fourier`, or `dcrt`), including inherent methods on coefficient types.
//! Coefficient modules own storage and coefficient arithmetic only.
//! Within arithmetic, use add/sub, negation, scalar arithmetic,
//! then precomputed-factor arithmetic, polynomial products, body operations and gadget injection.
//! Capability groups remain explicit.
//!
//! - [`common`]: constructors, byte I/O, zero initialization
//! - [`iter`]: ciphertext iterators
//! - [`monomial`]: coefficient-domain monomial products
//! - `fourier_monomial`: Fourier monomial subtraction with integer-scale factors
//! - `ntt_monomial`: NTT-domain monomial products with reusable scratch
//! - `ntt_polynomial`, [`dcrt_polynomial`]: same-domain polynomial products
//! - [`plaintext`], [`gadget`]: encoded body operations and gadget diagonal injection
//! - [`ops`], [`rns_ops`], `fourier_ops`: representation-specific arithmetic
//! - `ntt`, `fourier`: representation conversions and Fourier storage

#[macro_use]
mod common;
#[macro_use]
mod iter;
#[macro_use]
mod ops;
#[macro_use]
mod rns_ops;
#[cfg(feature = "fourier")]
#[macro_use]
mod fourier_ops;
#[cfg(feature = "ntt")]
#[macro_use]
mod ntt;
#[cfg(feature = "ntt")]
#[macro_use]
mod ntt_polynomial;
#[cfg(feature = "ntt")]
#[macro_use]
mod ntt_monomial;
#[cfg(feature = "fourier")]
#[macro_use]
mod fourier_monomial;
#[macro_use]
mod monomial;
#[macro_use]
mod dcrt_polynomial;
#[cfg(feature = "fourier")]
#[macro_use]
mod fourier;
#[macro_use]
mod plaintext;
#[macro_use]
mod gadget;
