#[cfg(feature = "concrete-ntt")]
mod concrete;
mod field_ntt_table;
mod numeric_ntt_table;

#[cfg(feature = "concrete-ntt")]
pub use concrete::prime32::Concrete32Table;
#[cfg(feature = "concrete-ntt")]
pub use concrete::prime64::Concrete64Table;
pub use field_ntt_table::FieldTableWithShoupRoot;
pub use numeric_ntt_table::TableWithShoupRoot;
