//! Polymorphic storage traits for contiguous buffers.
//!
//! The traits in this crate let algorithms work with contiguous storage
//! without committing to a particular container. [`Data`] provides shared
//! access, [`DataMut`] adds mutable access, and [`DataOwned`] adds owned
//! construction. `FromIterator` and `IntoIterator` are independent capabilities.
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
//! | `AVec<T, A>`¹   | ✓         | ✓      | ✓         | —           |
//! | `ABox<[T], A>`¹ | ✓         | ✓      | ✓         | —           |
//!
//! ¹ Requires the `aligned-vec` feature. They do not implement [`DataOwned`]
//! because construction must choose an alignment explicitly. Allocate them first,
//! then use the same `Data`/`DataMut` operations. References to any supported
//! sized backend forward its read capabilities; mutable references also forward
//! `DataMut` when the backend supports it.
//!
//! # Example
//!
//! ```
//! use primus_data::Data;
//!
//! fn sum<D: Data<Elem = u64>>(buf: &D) -> u64 {
//!     buf.iter().sum()
//! }
//!
//! assert_eq!(sum(&vec![1, 2, 3]), 6);
//! ```

#![deny(missing_docs)]

mod impls;
mod traits;

pub use traits::{Data, DataMut, DataOwned, RawData};
