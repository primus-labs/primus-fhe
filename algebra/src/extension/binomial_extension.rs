use core::fmt;
use std::{
    array,
    fmt::Display,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use itertools::Itertools;
use num_traits::{ConstOne, ConstZero, Inv, One, Pow, Zero};
use rand::{CryptoRng, Rng};
use rand_distr::{Distribution, Standard};
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    field_to_array, powers, AbstractExtensionField, ConstNegOne, ExtensionField, Field,
    FieldUniformSampler, HasFrobenius, HasTwoAdicBionmialExtension, NegOne, PackedField,
    TwoAdicField,
};

use super::{BinomiallyExtendable, Packable};

/// Binomial extension field
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
pub struct BinomialExtensionField<F, const D: usize> {
    pub(crate) value: [F; D],
}

impl<F: Field, const D: usize> Default for BinomialExtensionField<F, D> {
    #[inline]
    fn default() -> Self {
        Self {
            value: [F::ZERO; D],
        }
    }
}

impl<F: Field, const D: usize> From<F> for BinomialExtensionField<F, D> {
    #[inline]
    fn from(x: F) -> Self {
        Self {
            value: field_to_array(x),
        }
    }
}

impl<F: BinomiallyExtendable<D>, const D: usize> Packable for BinomialExtensionField<F, D> {}

impl<F: BinomiallyExtendable<D> + PackedField<Scalar = F> + Packable, const D: usize>
    ExtensionField<F> for BinomialExtensionField<F, D>
{
    type ExtensionPacking = BinomialExtensionField<F, D>;
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> HasFrobenius<F>
    for BinomialExtensionField<F, D>
{
    /// FrobeniusField automorphisms: x -> x^n, where n is the order of BaseField.
    fn frobenius(&self) -> Self {
        self.repeated_frobenius(1)
    }

    /// Repeated Frobenius automorphisms: x -> x^(n^count).
    ///
    /// Follows precomputation suggestion in Section 11.3.3 of the
    /// Handbook of Elliptic and Hyperelliptic Curve Cryptography.
    fn repeated_frobenius(&self, count: usize) -> Self {
        if count == 0 {
            return *self;
        } else if count >= D {
            // x |-> x^(n^D) is the identity, so x^(n^count) ==
            // x^(n^(count % D))
            return self.repeated_frobenius(count % D);
        }
        let arr: &[F] = self.as_base_slice();

        // z0 = DTH_ROOT^count = W^(k * count) where k = floor((n-1)/D)
        let mut z0 = F::dth_root();
        for _ in 1..count {
            z0 *= F::dth_root();
        }

        let mut res = [F::zero(); D];
        for (i, z) in powers(z0).take(D).enumerate() {
            res[i] = arr[i] * z;
        }

        Self::from_base_slice(&res)
    }

    /// Algorithm 11.3.4 in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
    fn frobenius_inv(&self) -> Self {
        // Writing 'a' for self, we need to compute a^(r-1):
        // r = n^D-1/n-1 = n^(D-1)+n^(D-2)+...+n
        let mut f = Self::one();
        for _ in 1..D {
            f = (f * *self).frobenius();
        }

        // g = a^r is in the base field, so only compute that
        // coefficient rather than the full product.
        let a = self.value;
        let b = f.value;
        let mut g = F::zero();
        for i in 1..D {
            g += a[i] * b[D - i];
        }
        g *= F::w();
        g += a[0] * b[0];
        debug_assert_eq!(Self::from(g), *self * f);

        f * g.inv()
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> AbstractExtensionField<F>
    for BinomialExtensionField<F, D>
{
    const D: usize = D;

    #[inline]
    fn from_base(b: F) -> Self {
        Self {
            value: field_to_array(b),
        }
    }

    #[inline]
    fn from_base_slice(bs: &[F]) -> Self {
        Self {
            value: bs.to_vec().try_into().expect("slice has wrong length"),
        }
    }

    #[inline]
    fn from_base_fn<Fn: FnMut(usize) -> F>(f: Fn) -> Self {
        Self {
            value: array::from_fn(f),
        }
    }

    #[inline]
    fn as_base_slice(&self) -> &[F] {
        &self.value
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> Field
    for BinomialExtensionField<F, D>
{
    type Value = F::Value;
    type Order = u128;

    #[inline]
    fn new(value: Self::Value) -> Self {
        Self {
            value: field_to_array(F::new(value)),
        }
    }

    const MODULUS_VALUE: Self::Value = F::MODULUS_VALUE;

    fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        Self::from_base_fn(|_| FieldUniformSampler::new().sample(rng))
    }

    /// This part is inaccurate.
    #[inline]
    fn value(self) -> Self::Value {
        self.value[0].value()
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> Display
    for BinomialExtensionField<F, D>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Self::zero() {
            write!(f, "0")
        } else {
            let str = self
                .value
                .iter()
                .enumerate()
                .filter(|(_, x)| !x.is_zero())
                .map(|(i, x)| match (i, x.is_one()) {
                    (0, _) => format!("{x}"),
                    (1, true) => "X".to_string(),
                    (1, false) => format!("{x} X"),
                    (_, true) => format!("X^{i}"),
                    (_, false) => format!("{x} X^{i}"),
                })
                .join(" + ");
            write!(f, "{}", str)
        }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Neg for BinomialExtensionField<F, D> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        Self {
            value: self.value.map(F::neg),
        }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Add for BinomialExtensionField<F, D> {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let mut res = self.value;
        for (r, rhs_val) in res.iter_mut().zip(rhs.value) {
            *r += rhs_val;
        }
        Self { value: res }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Add<F> for BinomialExtensionField<F, D> {
    type Output = Self;
    #[inline]
    fn add(self, rhs: F) -> Self::Output {
        let mut res = self.value;
        res[0] += rhs;
        Self { value: res }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> AddAssign
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Add<&Self>
    for BinomialExtensionField<F, D>
{
    type Output = Self;
    #[inline]
    fn add(self, rhs: &Self) -> Self::Output {
        self + *rhs
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> AddAssign<&Self>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        *self += *rhs
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> AddAssign<F>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn add_assign(&mut self, rhs: F) {
        *self = *self + rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Sub for BinomialExtensionField<F, D> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        let mut res = self.value;
        for (r, rhs_val) in res.iter_mut().zip(rhs.value) {
            *r -= rhs_val;
        }
        Self { value: res }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Sub<F> for BinomialExtensionField<F, D> {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: F) -> Self {
        let mut res = self.value;
        res[0] -= rhs;
        Self { value: res }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Sub<&Self>
    for BinomialExtensionField<F, D>
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: &Self) -> Self::Output {
        self - *rhs
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> SubAssign<&Self>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn sub_assign(&mut self, rhs: &Self) {
        *self -= *rhs
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> SubAssign
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> SubAssign<F>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn sub_assign(&mut self, rhs: F) {
        *self = *self - rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Mul for BinomialExtensionField<F, D> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.value;
        let b = rhs.value;
        let w = F::w();
        let w_af = w;

        match D {
            2 => {
                let mut res = Self::default();
                res.value[0] = a[0] * b[0] + a[1] * w_af * b[1];
                res.value[1] = a[0] * b[1] + a[1] * b[0];
                res
            }
            3 => Self {
                value: cubic_mul(&a, &b, w).to_vec().try_into().unwrap(),
            },
            _ => {
                let mut res = Self::default();
                #[allow(clippy::needless_range_loop)]
                for i in 0..D {
                    for j in 0..D {
                        if i + j >= D {
                            res.value[i + j - D] += a[i] * w_af * b[j];
                        } else {
                            res.value[i + j] += a[i] * b[j];
                        }
                    }
                }
                res
            }
        }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Mul<F> for BinomialExtensionField<F, D> {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: F) -> Self::Output {
        Self {
            value: self.value.map(|x| x * rhs),
        }
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Mul<&Self>
    for BinomialExtensionField<F, D>
{
    type Output = Self;

    #[inline]
    fn mul(self, rhs: &Self) -> Self::Output {
        self * (*rhs)
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> MulAssign<&Self>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn mul_assign(&mut self, rhs: &Self) {
        *self *= *rhs
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> MulAssign
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> MulAssign<F>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn mul_assign(&mut self, rhs: F) {
        *self = *self * rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> Div
    for BinomialExtensionField<F, D>
{
    type Output = Self;

    #[inline]
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * (rhs.inv())
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> Div<&Self>
    for BinomialExtensionField<F, D>
{
    type Output = Self;

    #[inline]
    fn div(self, rhs: &Self) -> Self::Output {
        self / (*rhs)
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> DivAssign
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> DivAssign<&Self>
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn div_assign(&mut self, rhs: &Self) {
        *self /= *rhs;
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> Inv
    for BinomialExtensionField<F, D>
{
    type Output = Self;
    #[inline]
    fn inv(self) -> Self::Output {
        self.try_inverse().expect("Tried to invert zero")
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> BinomialExtensionField<F, D> {
    #[inline]
    fn try_inverse(&self) -> Option<Self> {
        match D {
            2 => Some(Self {
                value: qudratic_inv(&self.value, F::w())
                    .to_vec()
                    .try_into()
                    .unwrap(),
            }),
            3 => Some(Self {
                value: cubic_inv(&self.value, F::w()).to_vec().try_into().unwrap(),
            }),
            _ => Some(self.frobenius_inv()),
        }
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> Zero
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn zero() -> Self {
        Self {
            value: [F::ZERO; D],
        }
    }

    #[inline]
    fn set_zero(&mut self) {
        self.value = [F::ZERO; D];
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.value == [F::ZERO; D]
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> ConstZero
    for BinomialExtensionField<F, D>
{
    const ZERO: Self = Self {
        value: [F::ZERO; D],
    };
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> One
    for BinomialExtensionField<F, D>
{
    #[inline]
    fn one() -> Self {
        Self {
            value: field_to_array(F::ONE),
        }
    }

    #[inline]
    fn set_one(&mut self) {
        *self = Self::one();
    }

    #[inline]
    fn is_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self::one()
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> ConstOne
    for BinomialExtensionField<F, D>
{
    const ONE: Self = Self {
        value: field_to_array(F::ONE),
    };
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> NegOne
    for BinomialExtensionField<F, D>
{
    fn neg_one() -> Self {
        Self {
            value: field_to_array(F::neg_one()),
        }
    }

    fn set_neg_one(&mut self) {
        *self = NegOne::neg_one();
    }

    fn is_neg_one(&self) -> bool
    where
        Self: PartialEq,
    {
        *self == Self::neg_one()
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> ConstNegOne
    for BinomialExtensionField<F, D>
{
    const NEG_ONE: Self = Self {
        value: field_to_array(F::NEG_ONE),
    };
}

impl<F: Field + BinomiallyExtendable<D>, const D: usize> Pow<u128>
    for BinomialExtensionField<F, D>
{
    type Output = Self;

    #[inline]
    // *****WARNING******
    // Need to re-implement
    fn pow(self, _rhs: u128) -> Self::Output {
        std::unimplemented!()
    }
}

impl<F: Field + BinomiallyExtendable<D> + Packable, const D: usize> BinomialExtensionField<F, D> {
    /// square
    #[inline(always)]
    pub fn square(&self) -> Self {
        match D {
            2 => {
                let a = self.value;
                let mut res = Self::default();
                res.value[0] = a[0] * a[0] + a[1] * a[1] * F::w();
                res.value[1] = (a[0] * a[1]) + (a[0] * a[1]);

                res
            }
            3 => Self {
                value: cubic_square(&self.value, F::w())
                    .to_vec()
                    .try_into()
                    .unwrap(),
            },
            _ => <Self as Mul<Self>>::mul(*self, *self),
        }
    }

    /// Returns a uniform random element.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::from_base_fn(|_| FieldUniformSampler::new().sample(rng))
    }
}

impl<F: BinomiallyExtendable<D> + Packable, const D: usize>
    Distribution<BinomialExtensionField<F, D>> for Standard
where
    Standard: Distribution<F>,
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BinomialExtensionField<F, D> {
        let mut res = [F::zero(); D];
        for r in res.iter_mut() {
            *r = Standard.sample(rng);
        }
        BinomialExtensionField::<F, D>::from_base_slice(&res)
    }
}

impl<F: Field + HasTwoAdicBionmialExtension<D> + Packable, const D: usize> TwoAdicField
    for BinomialExtensionField<F, D>
{
    const TWO_ADICITY: usize = F::EXT_TWO_ADICITY;

    fn two_adic_generator(bits: usize) -> Self {
        Self {
            value: F::ext_two_adic_generator(bits),
        }
    }
}

impl<F: Serialize, const D: usize> Serialize for BinomialExtensionField<F, D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(D))?;
        for item in &self.value {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl<'de, F: Deserialize<'de> + Default + Copy, const D: usize> Deserialize<'de>
    for BinomialExtensionField<F, D>
{
    fn deserialize<DE>(deserializer: DE) -> Result<Self, DE::Error>
    where
        DE: Deserializer<'de>,
    {
        struct ArrayVisitor<F, const D: usize> {
            marker: std::marker::PhantomData<F>,
        }

        impl<'de, F: Copy + Deserialize<'de> + Default, const D: usize> Visitor<'de>
            for ArrayVisitor<F, D>
        {
            type Value = BinomialExtensionField<F, D>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&format!("an array of length {}", D))
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut value = [F::default(); D];
                for (i, v) in value.iter_mut().enumerate().take(D) {
                    *v = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(BinomialExtensionField { value })
            }
        }

        deserializer.deserialize_seq(ArrayVisitor {
            marker: std::marker::PhantomData,
        })
    }
}

/// Section 11.3.6b in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
#[inline]
fn qudratic_inv<F: Field>(a: &[F], w: F) -> [F; 2] {
    let scalar = (a[0] * a[0] - w * a[1] * a[1]).inv();
    [a[0] * scalar, -a[1] * scalar]
}

/// Section 11.3.6b in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
#[inline]
fn cubic_inv<F: Field>(a: &[F], w: F) -> [F; 3] {
    let a0_square = a[0] * a[0];
    let a1_square = a[1] * a[1];
    let a2_w = w * a[2];
    let a0_a1 = a[0] * a[1];

    // scalar = (a0^3+wa1^3+w^2a2^3-3wa0a1a2)^-1
    let scalar = (a0_square * a[0] + w * a[1] * a1_square + a2_w * a2_w * a[2]
        - (F::one() + F::one() + F::one()) * a2_w * a0_a1)
        .inv();

    // scalar*[a0^2-wa1a2, wa2^2-a0a1, a1^2-a0a2]
    [
        scalar * (a0_square - a[1] * a2_w),
        scalar * (a2_w * a[2] - a0_a1),
        scalar * (a1_square - a[0] * a[2]),
    ]
}

/// karatsuba multiplication for cubic extension field
#[inline]
fn cubic_mul<F: Field>(a: &[F], b: &[F], w: F) -> [F; 3] {
    let a0_b0 = a[0] * b[0];
    let a1_b1 = a[1] * b[1];
    let a2_b2 = a[2] * b[2];

    let c0 = a0_b0 + ((a[1] + a[2]) * (b[1] + b[2]) - a1_b1 - a2_b2) * w;
    let c1 = (a[0] + a[1]) * (b[0] + b[1]) - a0_b0 - a1_b1 + a2_b2 * w;
    let c2 = (a[0] + a[2]) * (b[0] + b[2]) - a0_b0 - a2_b2 + a1_b1;

    [c0, c1, c2]
}

/// Section 11.3.6a in Handbook of Elliptic and Hyperelliptic Curve Cryptography.
#[inline]
fn cubic_square<F: Field>(a: &[F], w: F) -> [F; 3] {
    let w_a2 = a[2] * w;

    let c0 = a[0] * a[0] + (a[1] * w_a2) + (a[1] * w_a2);
    let c1 = w_a2 * a[2] + (a[0] * a[1]) + (a[0] * a[1]);
    let c2 = a[1] * a[1] + (a[0] * a[2]) + (a[0] * a[2]);

    [c0, c1, c2]
}
