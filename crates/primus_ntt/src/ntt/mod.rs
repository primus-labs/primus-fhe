use num_traits::{ConstOne, ConstZero};
use primus_factor::{FactorMul, ShoupFactor};
use primus_integer::FheUint;
use primus_reduce::FieldContext;
use primus_shape::PolyLength;

use crate::{NttError, reverse::reverse_lsbs};

mod prime32;
mod prime64;
mod primitive;

pub use prime32::U32NttTable;
pub use prime64::U64NttTable;
pub use primitive::UintNttTable;

/// Abstract interface for Number Theory Transform (NTT).
///
/// Forward transforms consume ascending-power coefficients and produce
/// bit-reversed evaluations. Inverse transforms restore coefficient order and
/// include inverse-length normalization. Slices carry no representation or
/// table identity; callers must preserve the originating table's convention.
///
/// # Slice length contract
///
/// Every input or output slice must contain exactly `self.poly_length().get()`
/// coefficients. [`Self::poly_length`] returns a [`PolyLength`], which establishes
/// the supported power-of-two geometry. Implementations must enforce the exact
/// slice length in release builds before writes or unchecked transform kernels.
pub trait NttTable: Sized + Send + Sync {
    /// The value type.
    type ValueT: FheUint;

    /// Creates a new [`NttTable`].
    ///
    /// The checked length establishes power-of-two geometry.
    ///
    /// # Errors
    ///
    /// Built-in tables reject insufficient lazy-arithmetic headroom with
    /// [`NttError::ModulusTooLarge`] before root search or table allocation.
    /// The generic table then checks that the root order `2N` fits the
    /// coefficient type ([`NttError::DegreeNotRepresentable`]) and that
    /// `N < modulus` ([`NttError::DegreeTooLarge`]). Root-search failure is
    /// reported as [`NttError::NoPrimitiveRoot`] with degree `2N`.
    ///
    /// # Correctness
    ///
    /// The modulus must be prime and admit a primitive `2N`-th root, where
    /// `N = poly_length.get()`. [`FieldContext`] supplies arithmetic but does
    /// not establish primality; root search does not validate it either. Transform values from
    /// different tables are interchangeable only when their roots, ordering and
    /// normalization agree, not merely their lengths and moduli.
    fn new<M>(poly_length: PolyLength, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>;

    /// Returns the checked coefficient count `N`.
    #[must_use]
    fn poly_length(&self) -> PolyLength;

    /// Returns the coefficient modulus used to build this table.
    fn modulus(&self) -> Self::ValueT;

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, 4*modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, 4*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast number theory transform in place.
    ///
    /// This function transforms a polynomial slice with coefficient in `[0, modulus)`
    /// to a ntt polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `poly` - inputs in normal order, outputs in bit-reversed order
    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, 2*modulus)`
    /// to a polynomial slice with coefficient in `[0, 2*modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]);

    /// Perform a fast inverse number theory transform in place.
    ///
    /// This function transforms a ntt polynomial slice with coefficient in `[0, modulus)`
    /// to a polynomial slice with coefficient in `[0, modulus)`.
    ///
    /// # Arguments
    ///
    /// * `values` - inputs in bit-reversed order, outputs in normal order
    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]);
}

/// NTT root data required to transform monomials directly.
///
/// This capability is separate from [`NttTable`]. Implementations expose the
/// forward and inverse roots already used by the full transforms, while the
/// shared default methods derive the required indices as needed.
pub trait MonomialNttTable: NttTable {
    /// Returns the first `N` root powers in bit-reversed order.
    ///
    /// Implementations must return exactly `N` entries.
    ///
    /// For `0 <= k < N`, entry `reverse_bits(k)` must represent `w^k`.
    fn root_powers(&self) -> &[Self::ValueT];

    /// Returns the inverse root powers in the scrambled order used by the
    /// inverse NTT. Implementations must return exactly `N` entries.
    ///
    /// Entry zero represents one. For `1 <= k < N`, entry
    /// `reverse_bits(k - 1) + 1` must represent `w^-k`.
    fn inv_root_powers(&self) -> &[Self::ValueT];

    /// Transforms the monomial `coeff * X^degree` directly into NTT form.
    ///
    /// Degree is interpreted modulo `2N`. Zero coefficients and degrees `0`
    /// or `N` use direct fills without reading either root array.
    ///
    /// # Panics
    ///
    /// Panics unless `values` contains exactly `N` entries, or if the root
    /// array used by the selected branch does not contain exactly `N` entries.
    /// These length checks precede any output writes.
    ///
    /// # Correctness
    ///
    /// `coeff` must be a canonical residue modulo [`NttTable::modulus`], that
    /// is, it must lie in `[0, self.modulus())`. This method does not reduce
    /// `coeff` before using it. Root values and ordering must satisfy
    /// [`Self::root_powers`] and [`Self::inv_root_powers`]; only lengths are checked.
    fn transform_monomial(&self, coeff: Self::ValueT, degree: usize, values: &mut [Self::ValueT]) {
        let n = self.poly_length().get();
        assert_ntt_length(values.len(), n);

        if coeff == Self::ValueT::ZERO {
            values.fill(Self::ValueT::ZERO);
            return;
        }

        let twice_n = 2 * n;
        let degree = degree & (twice_n - 1);

        if degree == 0 {
            values.fill(coeff);
            return;
        }

        let modulus = self.modulus();
        if degree == n {
            values.fill(modulus - coeff);
            return;
        }

        if degree.is_power_of_two() {
            let root_powers = self.root_powers();
            assert_eq!(
                root_powers.len(),
                n,
                "NTT forward root powers length mismatch"
            );
            let shift = degree.trailing_zeros();
            let index_shift = shift + 1;
            let index_prefix = n >> index_shift;
            return transform_monomial_from_root_indices(
                self,
                coeff,
                values,
                root_powers,
                index_shift,
                |group_index| (index_prefix | group_index, false),
            );
        }

        let inverse_degree = twice_n - degree;
        if inverse_degree.is_power_of_two() {
            let inv_root_powers = self.inv_root_powers();
            assert_eq!(
                inv_root_powers.len(),
                n,
                "NTT inverse root powers length mismatch"
            );

            let shift = inverse_degree.trailing_zeros();
            let index_shift = shift + 1;
            let index_prefix = n - (n >> shift) + 1;
            return transform_monomial_from_root_indices(
                self,
                coeff,
                values,
                inv_root_powers,
                index_shift,
                |group_index| (index_prefix + group_index, false),
            );
        }

        let root_powers = self.root_powers();
        assert_eq!(
            root_powers.len(),
            n,
            "NTT forward root powers length mismatch"
        );
        let log_n = n.trailing_zeros();
        let group_log = degree.trailing_zeros() + 1;
        let exponent_mask = twice_n - 1;
        let power_mask = n - 1;
        transform_monomial_from_root_indices(
            self,
            coeff,
            values,
            root_powers,
            group_log,
            |group_index| {
                let evaluation_index = reverse_lsbs(group_index, log_n - group_log);
                let exponent = ((2 * evaluation_index + 1) * degree) & exponent_mask;
                let power_index = reverse_lsbs(exponent & power_mask, log_n);
                (power_index, exponent & n != 0)
            },
        );
    }

    /// Transforms the monomial `X^degree` directly into NTT form.
    #[inline]
    fn transform_coeff_one_monomial(&self, degree: usize, values: &mut [Self::ValueT]) {
        self.transform_monomial(Self::ValueT::ONE, degree, values);
    }

    /// Transforms the monomial `-X^degree` directly into NTT form.
    #[inline]
    fn transform_coeff_minus_one_monomial(&self, degree: usize, values: &mut [Self::ValueT]) {
        self.transform_monomial(self.modulus() - Self::ValueT::ONE, degree, values);
    }
}

// The power of two dividing the degree groups equal evaluations in bit-reversed
// order. Each group consists of a constant half followed by its negation.
// The default dispatch checks the selected root slice has N entries and supplies
// indices in 0..N and an output divisible by the group size.
#[inline]
fn transform_monomial_from_root_indices<Table, IndexFn>(
    table: &Table,
    coeff: Table::ValueT,
    values: &mut [Table::ValueT],
    root_powers: &[Table::ValueT],
    group_log: u32,
    root_index: IndexFn,
) where
    Table: MonomialNttTable,
    IndexFn: Fn(usize) -> (usize, bool),
{
    if group_log == 1 {
        return transform_monomial_from_root_pairs(table, coeff, values, root_powers, root_index);
    }

    let modulus = table.modulus();
    let root_at = |group_index| {
        let (index, negate) = root_index(group_index);
        // SAFETY: dispatch checked the selected root length is N; its index
        // formula produces indices in 0..N for every output group.
        let root = unsafe { *root_powers.get_unchecked(index) };
        if negate { modulus - root } else { root }
    };
    let group_size = 1usize << group_log;
    let half_group_size = group_size >> 1;

    if coeff == Table::ValueT::ONE {
        values
            .chunks_exact_mut(group_size)
            .enumerate()
            .for_each(|(group_index, group)| {
                let first = root_at(group_index);
                let (first_half, second_half) = group.split_at_mut(half_group_size);
                first_half.fill(first);
                second_half.fill(modulus - first);
            });
    } else if coeff == modulus - Table::ValueT::ONE {
        values
            .chunks_exact_mut(group_size)
            .enumerate()
            .for_each(|(group_index, group)| {
                let second = root_at(group_index);
                let (first_half, second_half) = group.split_at_mut(half_group_size);
                first_half.fill(modulus - second);
                second_half.fill(second);
            });
    } else {
        let coeff = ShoupFactor::new(coeff, modulus);
        values
            .chunks_exact_mut(group_size)
            .enumerate()
            .for_each(|(group_index, group)| {
                let first = coeff.factor_mul_modulo(root_at(group_index), modulus);
                let (first_half, second_half) = group.split_at_mut(half_group_size);
                first_half.fill(first);
                second_half.fill(modulus - first);
            });
    }
}

// Odd degrees have groups of two. Fixed-size pairs avoid the general fill loops;
// dispatch establishes checked root length, valid indices and complete pairs.
#[inline]
fn transform_monomial_from_root_pairs<Table, IndexFn>(
    table: &Table,
    coeff: Table::ValueT,
    values: &mut [Table::ValueT],
    root_powers: &[Table::ValueT],
    root_index: IndexFn,
) where
    Table: MonomialNttTable,
    IndexFn: Fn(usize) -> (usize, bool),
{
    let modulus = table.modulus();
    let root_at = |pair_index| {
        let (index, negate) = root_index(pair_index);
        // SAFETY: dispatch checked the selected root length is N; its index
        // formula produces indices in 0..N for every output pair.
        let root = unsafe { *root_powers.get_unchecked(index) };
        if negate { modulus - root } else { root }
    };

    if coeff == Table::ValueT::ONE {
        values
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .enumerate()
            .for_each(|(pair_index, pair)| {
                let first = root_at(pair_index);
                pair[0] = first;
                pair[1] = modulus - first;
            });
    } else if coeff == modulus - Table::ValueT::ONE {
        values
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .enumerate()
            .for_each(|(pair_index, pair)| {
                let second = root_at(pair_index);
                pair[0] = modulus - second;
                pair[1] = second;
            });
    } else {
        let coeff = ShoupFactor::new(coeff, modulus);
        values
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .enumerate()
            .for_each(|(pair_index, pair)| {
                let first = coeff.factor_mul_modulo(root_at(pair_index), modulus);
                pair[0] = first;
                pair[1] = modulus - first;
            });
    }
}

#[track_caller]
#[inline]
fn assert_ntt_length(actual: usize, expected: usize) {
    assert_eq!(
        actual, expected,
        "NTT polynomial length mismatch: expected {expected}, got {actual}"
    );
}
