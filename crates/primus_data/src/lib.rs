//! Polymorphic storage traits for contiguous buffers.
//!
//! `primus_data` provides [`RawData`], [`Data`], [`DataMut`], and
//! [`DataOwned`] — a sealed hierarchy of traits that abstract over how a
//! contiguous sequence of elements is stored. Eight backends are supported
//! out of the box:
//!
//! | Backend         | `RawData` | `Data` | `DataMut` | `DataOwned` |
//! |-----------------|-----------|--------|-----------|-------------|
//! | `&[T]`          | ✓         | ✓      | —         | —           |
//! | `&mut [T]`      | ✓         | ✓      | ✓         | —           |
//! | `[T; N]`        | ✓         | ✓      | ✓         | —           |
//! | `&[T; N]`       | ✓         | ✓      | —         | —           |
//! | `&mut [T; N]`   | ✓         | ✓      | ✓         | —           |
//! | `Vec<T>`        | ✓         | ✓      | ✓         | ✓           |
//! | `Box<[T]>`      | ✓         | ✓      | ✓         | ✓           |
//! | `Arc<[T]>`      | ✓         | ✓      | —         | —           |
//!
//! # Usage
//!
//! Generic code that needs read-only access to a contiguous buffer bounds on
//! `Data`. Code that writes (fill, copy, split) also requires `DataMut`.
//! Callers that need to create a new owned buffer use `DataOwned`.
//!
//! ```ignore
//! fn sum<D: Data<Elem = u64>>(buf: &D) -> u64 {
//!     buf.as_slice().iter().sum()
//! }
//! ```

#![deny(missing_docs)]

mod impls;
mod traits;

pub use traits::{Data, DataMut, DataOwned, RawData};
