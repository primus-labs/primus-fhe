//! Single-modulus NTT-domain GLWE public-key encryption.

use primus_data::{Data, DataMut, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{GlweEncryptionParameters, NttGlweCiphertext, NttGlweSecretKey};

/// A GLWE public key represented by one NTT-domain encryption of zero.
///
/// # Correctness
///
/// Key values must be canonical residues in the same modulus and NTT
/// representation as subsequent encryption calls. Raw ciphertext and byte
/// conversions do not validate this property.
#[derive(Clone)]
pub struct NttGlwePublicKey<S>
where
    S: RawData,
    <S as RawData>::Elem: FheUint,
{
    key: NttGlweCiphertext<S>,
}

impl<S, T> AsRef<[T]> for NttGlwePublicKey<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.key.as_ref()
    }
}

impl<S, T> AsMut<[T]> for NttGlwePublicKey<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        self.key.as_mut()
    }
}

impl<S, T> From<NttGlweCiphertext<S>> for NttGlwePublicKey<S>
where
    S: RawData<Elem = T>,
    T: FheUint,
{
    #[inline]
    fn from(key: NttGlweCiphertext<S>) -> Self {
        Self { key }
    }
}

impl<T: FheUint> NttGlwePublicKey<Vec<T>> {
    /// Generates a public key for `secret_key` by encrypting zero.
    ///
    /// # Panics
    ///
    /// Panics on the layout and transform mismatches described by
    /// [`NttGlweSecretKey::encrypt_zeros`].
    #[must_use]
    pub fn generate<M, Table, R>(
        secret_key: &NttGlweSecretKey<T>,
        params: &GlweEncryptionParameters<T, M>,
        ntt_table: &Table,
        rng: &mut R,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        Self {
            key: secret_key.encrypt_zeros(params, ntt_table, rng),
        }
    }
}

mod bytes;
mod encrypt;
mod message;
mod workspace;
pub use workspace::NttGlwePublicEncryptWorkspace;
