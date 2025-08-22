use algebra::{
    ntt::NumberTheoryTransform,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    random::DiscreteGaussian,
    reduce::{ReduceNeg, ReduceNegAssign},
    utils::Size,
    ByteCount, Field, NttField,
};
use rand::{prelude::Distribution, CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::Lwe;

/// Sparse Rlwe ciphertext.
#[derive(Serialize, Deserialize)]
#[serde(bound = "F: Field")]
pub struct SparseRlwe<F: Field> {
    /// Represents the first component in the RLWE structure.
    /// It is a polynomial where the coefficients are elements of the field `F`.
    pub(crate) a: FieldPolynomial<F>,
    /// Represents the second component in the RLWE structure.
    /// It's also a polynomial with coefficients in the field `F`.
    pub(crate) b: Vec<<F as Field>::ValueT>,
}

impl<F: Field> Eq for SparseRlwe<F> {}

impl<F: Field> PartialEq for SparseRlwe<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: Field> Clone for SparseRlwe<F> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            b: self.b.clone(),
        }
    }
}

impl<F: Field> Default for SparseRlwe<F> {
    #[inline]
    fn default() -> Self {
        Self {
            a: FieldPolynomial::new(Vec::new()),
            b: Vec::new(),
        }
    }
}

impl<F: Field> SparseRlwe<F> {
    /// Creates a new [`SparseRlwe<F>`] from bytes `data`.
    #[inline]
    pub fn from_bytes(data: &[u8], dimension: usize) -> Self {
        let converted_data: &[F::ValueT] = bytemuck::cast_slice(data);

        let (a, b) = converted_data.split_at(dimension);

        Self {
            a: FieldPolynomial::from_slice(a),
            b: b.to_vec(),
        }
    }

    /// Creates a new [`SparseRlwe<F>`] from bytes `data`.
    #[inline]
    pub fn from_bytes_assign(&mut self, data: &[u8]) {
        let converted_data: &[F::ValueT] = bytemuck::cast_slice(data);

        let (a, b) = converted_data.split_at(self.a.coeff_count());

        self.a.copy_from(a);
        self.b.copy_from_slice(b);
    }

    /// Converts [`SparseRlwe<F>`] into bytes.
    #[inline]
    pub fn into_bytes(&self) -> Vec<u8> {
        let data_a: &[u8] = bytemuck::cast_slice(self.a.as_slice());
        let data_b: &[u8] = bytemuck::cast_slice(self.b.as_slice());

        [data_a, data_b].concat()
    }

    /// Converts [`SparseRlwe<F>`] into bytes, stored in `data``.
    #[inline]
    pub fn into_bytes_inplace(&self, data: &mut [u8]) {
        let data_a: &[u8] = bytemuck::cast_slice(self.a.as_slice());
        let data_b: &[u8] = bytemuck::cast_slice(self.b.as_slice());

        assert_eq!(data.len(), data_a.len() + data_b.len());

        let (a, b) = unsafe { data.split_at_mut_unchecked(data_a.len()) };

        a.copy_from_slice(data_a);
        b.copy_from_slice(data_b);
    }

    /// Returns the bytes count of [`SparseRlwe<T>`].
    #[inline]
    pub fn bytes_count(&self) -> usize {
        (self.a.coeff_count() + self.b.len()) * <F::ValueT as ByteCount>::BYTES_COUNT
    }
}

impl<F: Field> SparseRlwe<F> {
    /// Creates a new [`SparseRlwe<F>`].
    #[inline]
    pub fn new(a: FieldPolynomial<F>, b: Vec<<F as Field>::ValueT>) -> Self {
        Self { a, b }
    }

    /// Creates a new [`SparseRlwe<F>`] with reference of [`FieldPolynomial<F>`].
    #[inline]
    pub fn from_ref(a: &FieldPolynomial<F>, b: &[<F as Field>::ValueT]) -> Self {
        Self {
            a: a.clone(),
            b: b.to_vec(),
        }
    }

    /// Creates a new [`SparseRlwe<F>`].
    #[inline]
    pub fn from_vec(mut data: Vec<<F as Field>::ValueT>, dimension: usize) -> Self {
        let b = data.split_off(dimension);
        Self {
            a: FieldPolynomial::new(data),
            b,
        }
    }

    /// Given inner data.
    #[inline]
    pub fn into_vec(mut self) -> Vec<<F as Field>::ValueT> {
        let mut a = self.a.inner_data();
        a.append(&mut self.b);
        a
    }

    /// Returns a reference to the `a` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn a(&self) -> &FieldPolynomial<F> {
        &self.a
    }

    /// Returns a reference to the `b` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn b(&self) -> &[<F as Field>::ValueT] {
        &self.b
    }

    /// Returns a mutable reference to the `a` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn a_mut(&mut self) -> &mut FieldPolynomial<F> {
        &mut self.a
    }

    /// Returns a mutable reference to the `b` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn b_mut(&mut self) -> &mut [<F as Field>::ValueT] {
        &mut self.b
    }

    /// Returns a mutable reference to the `a` and `b` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn a_b_mut(&mut self) -> (&mut FieldPolynomial<F>, &mut [<F as Field>::ValueT]) {
        (&mut self.a, &mut self.b)
    }

    /// Extracts a slice of `a` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn a_slice(&self) -> &[<F as Field>::ValueT] {
        self.a.as_slice()
    }

    /// Extracts a mutable slice of `a` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn a_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.a.as_mut_slice()
    }

    /// Extracts a slice of `b` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn b_slice(&self) -> &[<F as Field>::ValueT] {
        self.b.as_slice()
    }

    /// Extracts a mutable slice of `b` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn b_mut_slice(&mut self) -> &mut [<F as Field>::ValueT] {
        self.b.as_mut_slice()
    }

    /// Extracts mutable slice of `a` and `b` of this [`SparseRlwe<F>`].
    #[inline]
    pub fn a_b_mut_slices(&mut self) -> (&mut [<F as Field>::ValueT], &mut [<F as Field>::ValueT]) {
        (self.a.as_mut_slice(), self.b.as_mut_slice())
    }

    /// Gets the dimension of this [`SparseRlwe<F>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.a.coeff_count()
    }

    /// Returns the message count of this [`SparseRlwe<T>`].
    #[inline]
    pub fn msg_count(&self) -> usize {
        self.b.len()
    }

    /// Creates a new [`SparseRlwe<F>`] that is initialized to zero.
    ///
    /// The `coeff_count` parameter specifies the number of coefficients in the polynomial.
    /// Both `a` and `b` polynomials of the [`SparseRlwe<F>`] are initialized with zero coefficients.
    ///
    /// # Arguments
    ///
    /// * `coeff_count` - The number of coefficients in the polynomial.
    ///
    /// # Returns
    ///
    /// A new [`SparseRlwe<F>`] where both `a` and `b` polynomials are initialized to zero.
    #[inline]
    pub fn zero(coeff_count: usize, msg_count: usize) -> Self {
        Self {
            a: FieldPolynomial::zero(coeff_count),
            b: vec![<F as Field>::ZERO; msg_count],
        }
    }

    /// Set all entries equal to zero.
    #[inline]
    pub fn set_zero(&mut self) {
        self.a.set_zero();
        self.b.fill(<F as Field>::ZERO);
    }

    /// Perform element-wise addition of two [`SparseRlwe<F>`].
    #[inline]
    pub fn add_element_wise(mut self, rhs: &Self) -> Self {
        self.b.iter_mut().zip(rhs.b.iter()).for_each(|(x, &y)| {
            F::add_assign(x, y);
        });
        Self {
            a: self.a + rhs.a(),
            b: self.b,
        }
    }

    /// Perform element-wise subtraction of two [`SparseRlwe<F>`].
    #[inline]
    pub fn sub_element_wise(mut self, rhs: &Self) -> Self {
        self.b.iter_mut().zip(rhs.b.iter()).for_each(|(x, &y)| {
            F::sub_assign(x, y);
        });
        Self {
            a: self.a - rhs.a(),
            b: self.b,
        }
    }

    /// Performs an in-place element-wise addition
    /// on the `self` [`SparseRlwe<F>`] with another `rhs` [`SparseRlwe<F>`].
    #[inline]
    pub fn add_assign_element_wise(&mut self, rhs: &Self) {
        self.a += rhs.a();
        self.b.iter_mut().zip(rhs.b.iter()).for_each(|(x, &y)| {
            F::add_assign(x, y);
        });
    }

    /// Performs an in-place element-wise subtraction
    /// on the `self` [`SparseRlwe<F>`] with another `rhs` [`SparseRlwe<F>`].
    #[inline]
    pub fn sub_assign_element_wise(&mut self, rhs: &Self) {
        self.a -= rhs.a();
        self.b.iter_mut().zip(rhs.b.iter()).for_each(|(x, &y)| {
            F::sub_assign(x, y);
        });
    }

    /// Performs an in-place constant multiplication
    /// on the `self` [`SparseRlwe<F>`] with scalar `<F as Field>::ValueT`.
    #[inline]
    pub fn mul_scalar_assign(&mut self, scalar: <F as Field>::ValueT) {
        self.a.mul_scalar_assign(scalar);
        self.b.iter_mut().for_each(|v| F::mul_assign(v, scalar));
    }

    /// Performs addition operation:`self + rhs`,
    /// and puts the result to the `destination`.
    #[inline]
    pub fn add_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.a.add_inplace(rhs.a(), destination.a_mut());
        destination
            .b_mut()
            .iter_mut()
            .zip(self.b.iter())
            .zip(rhs.b().iter())
            .for_each(|((d, &x), &y)| *d = F::add(x, y));
    }

    /// Performs subtraction operation:`self - rhs`,
    /// and put the result to the `destination`.
    #[inline]
    pub fn sub_inplace(&self, rhs: &Self, destination: &mut Self) {
        self.a.sub_inplace(rhs.a(), destination.a_mut());
        destination
            .b_mut()
            .iter_mut()
            .zip(self.b.iter())
            .zip(rhs.b().iter())
            .for_each(|((d, &x), &y)| *d = F::sub(x, y));
    }

    /// Extract an LWE sample from SparseRlwe.
    #[inline]
    pub fn extract_lwe_with_index(&self, index: usize) -> Lwe<<F as Field>::ValueT> {
        let split = index + 1;

        let mut a: Vec<_> = self.a_slice().to_vec();

        a[..split].reverse();
        a[split..].reverse();
        a[split..]
            .iter_mut()
            .for_each(|x| F::MODULUS.reduce_neg_assign(x));

        Lwe::new(a, self.b[index])
    }

    /// Extract an LWE sample from SparseRlwe.
    #[inline]
    pub fn extract_lwe(&self) -> Lwe<<F as Field>::ValueT> {
        let mut a: Vec<_> = self.a.iter().map(|&x| F::MODULUS.reduce_neg(x)).collect();
        a[1..].reverse();
        F::MODULUS.reduce_neg_assign(&mut a[0]);

        Lwe::new(a, self.b[0])
    }

    /// Extract an LWE sample from SparseRlwe.
    #[inline]
    pub fn extract_lwe_locally(self) -> Lwe<<F as Field>::ValueT> {
        let Self { a, b } = self;
        let mut a = a.inner_data();
        a[1..].reverse();
        a[1..]
            .iter_mut()
            .for_each(|v| F::MODULUS.reduce_neg_assign(v));

        Lwe::new(a, b[0])
    }
}

impl<F: NttField> SparseRlwe<F> {
    /// Generate a `SparseRlwe<F>` sample which encrypts `0`.
    pub fn generate_random_zero_sample<R>(
        msg_count: usize,
        secret_key: &FieldNttPolynomial<F>,
        gaussian: DiscreteGaussian<<F as Field>::ValueT>,
        ntt_table: &<F as NttField>::Table,
        rng: &mut R,
    ) -> Self
    where
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = secret_key.coeff_count();
        let a = <FieldPolynomial<F>>::random(rlwe_dimension, rng);

        let mut a_ntt = ntt_table.transform(&a);
        a_ntt *= secret_key;

        let b = ntt_table
            .inverse_transform_inplace(a_ntt)
            .iter()
            .zip(gaussian.sample_iter(rng).take(msg_count))
            .map(|(x, y): (&<F as Field>::ValueT, <F as Field>::ValueT)| F::add(*x, y))
            .collect();

        Self { a, b }
    }
}

impl<F: Field> Size for SparseRlwe<F> {
    #[inline]
    fn size(&self) -> usize {
        self.a.size() + self.b.size()
    }
}
