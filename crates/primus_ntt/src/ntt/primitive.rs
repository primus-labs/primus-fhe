use primus_factor::{FactorMul, LazyFactorMul, ShoupFactor};
use primus_integer::FheUint;
use primus_modulus::common::compact;
use primus_reduce::FieldContext;
use primus_shape::PolyLength;

use crate::{NttError, reverse::reverse_lsbs, root::try_minimal_primitive_root};

use super::{MonomialNttTable, NttTable, assert_ntt_length};

/// Generic negacyclic NTT table using Shoup multiplication.
///
/// Forward and inverse transforms follow [`NttTable`]'s bit-reversed order,
/// residue ranges and inverse-length normalization. Direct monomial transforms
/// use the root layouts specified by [`MonomialNttTable`].
///
/// # Constraints
///
/// The modulus must satisfy `1 < modulus < 2^(T::BITS - 2)` so every lazy
/// intermediate in `[0, 4 * modulus)` is representable by `T`.
pub struct UintNttTable<T: FheUint> {
    modulus: T,
    poly_length: PolyLength,
    inv_n: ShoupFactor<T>,
    /// `inv_n * inv_root_powers[n-1] mod q` — precomputed for the inverse final stage.
    inv_n_r: ShoupFactor<T>,
    root_powers: Vec<T>,
    root_powers_precon: Vec<T>,
    inv_root_powers: Vec<T>,
    inv_root_powers_precon: Vec<T>,
}

impl<T: FheUint> NttTable for UintNttTable<T> {
    type ValueT = T;

    #[inline]
    fn new<M>(poly_length: PolyLength, modulus: M) -> Result<Self, NttError<Self::ValueT>>
    where
        M: FieldContext<Self::ValueT>,
    {
        let log_n = poly_length.log_n();
        let n = poly_length.get();
        let modulus_value = modulus.value();
        let max_bits = T::BITS - crate::NTT_LAZY_REDUCTION_HEADROOM_BITS;
        if modulus_value >= T::ONE << max_bits {
            return Err(NttError::ModulusTooLarge {
                modulus: modulus_value,
                max_bits,
            });
        }

        // Root search needs 2N in T, not just N. Check before its word-width
        // assertion or any table allocation. PolyLength guarantees 2N fits usize.
        let root_degree = T::try_from(2 * n).map_err(|_| NttError::DegreeNotRepresentable {
            degree: 2 * n,
            modulus: modulus_value,
        })?;
        let n_cast = root_degree >> 1u32;
        if n_cast >= modulus_value {
            return Err(NttError::DegreeTooLarge {
                degree: n,
                modulus: modulus_value,
            });
        }

        let root = try_minimal_primitive_root(log_n + 1, modulus)?;
        let modulus = modulus_value;

        let to_root_type = |x| -> ShoupFactor<T> { <ShoupFactor<T>>::new(x, modulus) };

        let root_factor = to_root_type(root);
        let inv_root = compact::reduce_inv(modulus, root);

        debug_assert_eq!(root_factor.factor_mul_modulo(inv_root, modulus), T::ONE);

        let mut root_powers = vec![T::ZERO; n];
        let mut power = T::ONE;
        for i in 0..n {
            root_powers[reverse_lsbs(i, log_n)] = power;
            power = root_factor.factor_mul_modulo(power, modulus);
        }
        let root_powers_precon = root_powers
            .iter()
            .map(|&root| ShoupFactor::quotient_for(root, modulus))
            .collect();

        let inv_root_factor = to_root_type(inv_root);
        let mut inv_root_powers = vec![T::ZERO; n];
        inv_root_powers[0] = T::ONE;
        let mut inv_power = inv_root;
        for i in 0..n - 1 {
            inv_root_powers[reverse_lsbs(i, log_n) + 1] = inv_power;
            inv_power = inv_root_factor.factor_mul_modulo(inv_power, modulus);
        }
        let inv_root_powers_precon = inv_root_powers
            .iter()
            .map(|&root| ShoupFactor::quotient_for(root, modulus))
            .collect::<Vec<_>>();

        let inv_n = to_root_type(compact::reduce_inv(modulus, n_cast));

        let inv_n_r = ShoupFactor::from_raw(
            *inv_root_powers.last().unwrap(),
            *inv_root_powers_precon.last().unwrap(),
        )
        .factor_mul_modulo(inv_n.value(), modulus);
        let inv_n_r = ShoupFactor::new(inv_n_r, modulus);

        Ok(Self {
            modulus,
            poly_length,
            inv_n,
            inv_n_r,
            root_powers,
            root_powers_precon,
            inv_root_powers,
            inv_root_powers_precon,
        })
    }

    #[inline(always)]
    fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    #[inline]
    fn modulus(&self) -> Self::ValueT {
        self.modulus
    }

    #[inline]
    fn lazy_transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        assert_ntt_length(poly.len(), self.poly_length.get());

        let modulus = self.modulus;
        let twice_modulus = modulus << 1u32;

        let roots = &self.root_powers;
        let roots_precon = &self.root_powers_precon;
        let mut root_index = 1usize;

        for gap in (0..self.poly_length.log_n()).rev().map(|x| 1usize << x) {
            for vc in poly.chunks_exact_mut(gap << 1) {
                // The transform consumes roots 1..N exactly once.
                let root = unsafe {
                    ShoupFactor::from_raw(
                        *roots.get_unchecked(root_index),
                        *roots_precon.get_unchecked(root_index),
                    )
                };
                root_index += 1;
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = compact::reduce_once(twice_modulus, *i);
                    let v = root.lazy_factor_mul_modulo(*j, modulus);
                    *i = u + v;
                    *j = u + twice_modulus - v;
                }
            }
        }
    }

    fn transform_slice(&self, poly: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_transform_slice(poly);

        let modulus = self.modulus;
        let twice_modulus = modulus << 1u32;
        poly.iter_mut().for_each(|v| {
            *v = compact::reduce_once(modulus, compact::reduce_once(twice_modulus, *v));
        });
    }

    fn lazy_inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        assert_ntt_length(values.len(), self.poly_length.get());

        let log_n = self.poly_length.log_n();

        let modulus = self.modulus;
        let twice_modulus = modulus << 1u32;

        let roots = &self.inv_root_powers;
        let roots_precon = &self.inv_root_powers_precon;
        let mut root_index = 1usize;

        for gap in (0..log_n - 1).map(|x| 1usize << x) {
            for vc in values.chunks_exact_mut(gap << 1) {
                // The non-final stages consume roots 1..N/2 exactly once.
                let root = unsafe {
                    ShoupFactor::from_raw(
                        *roots.get_unchecked(root_index),
                        *roots_precon.get_unchecked(root_index),
                    )
                };
                root_index += 1;
                let (v0, v1) = vc.split_at_mut(gap);
                for (i, j) in core::iter::zip(v0, v1) {
                    let u = *i;
                    let v = *j;
                    *i = compact::reduce_add(twice_modulus, u, v);
                    *j = root.lazy_factor_mul_modulo(u + twice_modulus - v, modulus);
                }
            }
        }

        let gap = 1 << (log_n - 1);

        let scalar = self.inv_n;
        let scaled_r = self.inv_n_r;

        let (v0, v1) = values.split_at_mut(gap);
        for (i, j) in core::iter::zip(v0, v1) {
            let u = *i;
            let v = *j;
            *i = scalar.factor_mul_modulo(u + v, modulus);
            *j = scaled_r.factor_mul_modulo(u + twice_modulus - v, modulus);
        }
    }

    fn inverse_transform_slice(&self, values: &mut [<Self as NttTable>::ValueT]) {
        self.lazy_inverse_transform_slice(values);

        let modulus = self.modulus;
        values.iter_mut().for_each(|v| {
            compact::reduce_once_assign(modulus, v);
        });
    }
}

impl<T: FheUint> MonomialNttTable for UintNttTable<T> {
    #[inline]
    fn root_powers(&self) -> &[Self::ValueT] {
        &self.root_powers
    }

    #[inline]
    fn inv_root_powers(&self) -> &[Self::ValueT] {
        &self.inv_root_powers
    }
}
