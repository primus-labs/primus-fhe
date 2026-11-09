use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_poly::Polynomial;
use primus_reduce::RingContext;

/// A cryptographic structure for NTRU.
///
/// ## Structure of the `data`
///
/// |------h------|
///
/// where `h` is one coefficient-domain [`Polynomial`]. Its phase under
/// secret polynomial `f` is `f * h` modulo `X^N + 1` and the ciphertext
/// modulus. Encryption requires the appropriate invertible NTRU secret;
/// this storage wrapper does not construct or validate it.
///
/// # Correctness
///
/// The layout above is a caller-maintained contract. Raw construction and
/// mutable storage access do not validate it; parameter and key metadata
/// are not stored in this wrapper. See the [crate contracts](crate#correctness).
#[derive(Clone)]
pub struct Ntru<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Ntru);

impl_iters!(Ntru);

impl_basic_operation_single_modulus!(Ntru);
impl_neg_single_modulus!(Ntru);
impl_mul_scalar_single_modulus!(Ntru);
impl_mul_factor_single_modulus!(Ntru);

impl<S, T> Ntru<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Multiplies this ciphertext by `X^exponent` and writes the output.
    ///
    /// # Correctness
    ///
    /// `exponent` must belong to `[0, 2N)`.
    /// Input and output each contain one polynomial of the same supported
    /// nonzero power-of-two length `N`. Values must be canonical under
    /// `modulus`; output is overwritten with canonical residues.
    #[inline]
    pub fn mul_monomial_to<M, A>(&self, exponent: usize, output: &mut Ntru<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        Polynomial(self.as_ref()).mul_monomial_to(
            exponent,
            &mut Polynomial(output.as_mut()),
            modulus,
        );
    }

    /// Computes `output = self * (X^exponent - 1)`.
    ///
    /// # Correctness
    ///
    /// `exponent` must belong to `[0, 2N)`.
    /// Input and output each contain one polynomial of the same supported
    /// nonzero power-of-two length `N`. Values must be canonical under
    /// `modulus`; output is overwritten with canonical residues.
    #[inline]
    pub fn mul_monomial_sub_one_to<M, A>(&self, exponent: usize, output: &mut Ntru<A>, modulus: M)
    where
        M: RingContext<T>,
        A: DataMut<Elem = T>,
    {
        Polynomial(self.as_ref()).mul_monomial_sub_one_to(
            exponent,
            &mut Polynomial(output.as_mut()),
            modulus,
        );
    }
}

impl<S, T> Ntru<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Multiplies this polynomial ciphertext by `X^exponent` without allocation.
    ///
    /// # Correctness
    ///
    /// The polynomial length `N` must be a supported power of two, and `exponent`
    /// must be in `[0, 2N)`. Canonical input residues produce canonical output.
    #[inline]
    pub fn mul_monomial_assign<M>(&mut self, exponent: usize, modulus: M)
    where
        M: Copy + primus_reduce::ReduceNegSlice<T>,
    {
        Polynomial(self.as_mut()).mul_monomial_assign(exponent, modulus);
    }

    /// Accumulates `self += rhs * X^exponent` in `Z_q[X]/(X^N + 1)`.
    ///
    /// # Correctness
    ///
    /// Both ciphertexts must contain a polynomial of the same nonzero power-of-two
    /// length `N`, use compatible keys, and contain canonical residues. `exponent`
    /// must be in `[0, 2N)`. Results are canonical; no temporary storage is allocated.
    #[inline]
    pub fn add_mul_monomial_assign<M, A>(&mut self, rhs: &Ntru<A>, exponent: usize, modulus: M)
    where
        M: Copy + primus_reduce::ReduceAddSlice<T> + primus_reduce::ReduceSubSlice<T>,
        A: Data<Elem = T>,
    {
        Polynomial(self.as_mut()).add_mul_monomial_assign(
            &Polynomial(rhs.as_ref()),
            exponent,
            modulus,
        );
    }
}
