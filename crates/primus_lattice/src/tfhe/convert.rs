use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};
use primus_fft::{FftTable, TorusFftValue};

use crate::ggsw::Ggsw;
use crate::ggsw::fourier::FourierGgsw;
use crate::glev::Glev;
use crate::glev::fourier::FourierGlev;
use crate::glwe::Glwe;
use crate::glwe::fourier::FourierGlwe;

// ---------------------------------------------------------------------------
// Forward: coefficient (torus) → Fourier (Complex64)
// ---------------------------------------------------------------------------

impl<S, T> Glwe<S>
where
    S: RawData<Elem = T> + Data,
    T: TorusFftValue,
{
    /// Writes this coefficient-domain GLWE into a Fourier-domain [`FourierGlwe`].
    ///
    /// Each coefficient polynomial (chunked by `fft.poly_length()`) is forward-
    /// transformed into a Fourier polynomial (chunked by `fft.fourier_length()`).
    #[inline]
    pub fn write_fourier_form<Table, A>(&self, result: &mut FourierGlwe<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = Complex64> + DataMut,
    {
        for (coeff, fourier) in self
            .as_ref()
            .chunks_exact(fft.poly_length())
            .zip(result.as_mut().chunks_exact_mut(fft.fourier_length()))
        {
            fft.forward_torus_slice(coeff, fourier);
        }
    }
}

impl<S, T> Glev<S>
where
    S: RawData<Elem = T> + Data,
    T: TorusFftValue,
{
    /// Writes this coefficient-domain GLev into a Fourier-domain [`FourierGlev`].
    #[inline]
    pub fn write_fourier_form<Table, A>(&self, result: &mut FourierGlev<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = Complex64> + DataMut,
    {
        for (coeff, fourier) in self
            .as_ref()
            .chunks_exact(fft.poly_length())
            .zip(result.as_mut().chunks_exact_mut(fft.fourier_length()))
        {
            fft.forward_torus_slice(coeff, fourier);
        }
    }
}

impl<S, T> Ggsw<S>
where
    S: RawData<Elem = T> + Data,
    T: TorusFftValue,
{
    /// Writes this coefficient-domain GGSW into a Fourier-domain [`FourierGgsw`].
    #[inline]
    pub fn write_fourier_form<Table, A>(&self, result: &mut FourierGgsw<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = Complex64> + DataMut,
    {
        for (coeff, fourier) in self
            .as_ref()
            .chunks_exact(fft.poly_length())
            .zip(result.as_mut().chunks_exact_mut(fft.fourier_length()))
        {
            fft.forward_torus_slice(coeff, fourier);
        }
    }
}

// ---------------------------------------------------------------------------
// Inverse: Fourier (Complex64) → coefficient (torus)
// ---------------------------------------------------------------------------

impl<S> FourierGlwe<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Writes this Fourier-domain GLWE back into a coefficient-domain [`Glwe`].
    ///
    /// Each Fourier polynomial (chunked by `fft.fourier_length()`) is inverse-
    /// transformed into a coefficient polynomial (chunked by `fft.poly_length()`).
    #[inline]
    pub fn write_torus_form<Table, A, T>(&self, result: &mut Glwe<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        for (fourier, coeff) in self
            .as_ref()
            .chunks_exact(fft.fourier_length())
            .zip(result.as_mut().chunks_exact_mut(fft.poly_length()))
        {
            fft.inverse_torus_slice(fourier, coeff);
        }
    }
}

impl<S> FourierGlev<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Writes this Fourier-domain GLev back into a coefficient-domain [`Glev`].
    #[inline]
    pub fn write_torus_form<Table, A, T>(&self, result: &mut Glev<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        for (fourier, coeff) in self
            .as_ref()
            .chunks_exact(fft.fourier_length())
            .zip(result.as_mut().chunks_exact_mut(fft.poly_length()))
        {
            fft.inverse_torus_slice(fourier, coeff);
        }
    }
}

impl<S> FourierGgsw<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Writes this Fourier-domain GGSW back into a coefficient-domain [`Ggsw`].
    #[inline]
    pub fn write_torus_form<Table, A, T>(&self, result: &mut Ggsw<A>, fft: &Table)
    where
        Table: FftTable,
        A: RawData<Elem = T> + DataMut,
        T: TorusFftValue,
    {
        for (fourier, coeff) in self
            .as_ref()
            .chunks_exact(fft.fourier_length())
            .zip(result.as_mut().chunks_exact_mut(fft.poly_length()))
        {
            fft.inverse_torus_slice(fourier, coeff);
        }
    }
}
