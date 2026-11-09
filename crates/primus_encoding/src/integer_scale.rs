use super::helpers::{centered_negative_start, lift_centered_from_raw};
use crate::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_reduce::{Modulus, ReduceAdd};

/// Integer multiplication for fixed-scale encoding.
/// The owning codec guarantees `delta > 0` and `(t-1)*delta < q` for `t >= 2`,
/// so magnitude products fit one word and are canonical without modular
/// multiplication. `NativeModulus<T>` denotes `q = 2^T::BITS`.
#[derive(Clone, Copy, Debug)]
pub(super) struct IntegerScale<T: FheUint> {
    op: ScaleOp<T>,
}

/// Magnitude scaling selected at construction, independent of the modulus.
#[derive(Clone, Copy, Debug)]
enum ScaleOp<T> {
    Shift { shift: u32 },
    Multiply { delta: T },
}

impl<T: FheUint> IntegerScale<T> {
    /// Selects a shift or multiplication for the integer scale.
    ///
    /// # Correctness
    ///
    /// The owning codec must establish the scale/modulus invariant documented
    /// on [`IntegerScale`]; this constructor does not validate it.
    pub(super) fn new(delta: T) -> Self {
        let op = if delta.is_power_of_two() {
            ScaleOp::Shift {
                shift: delta.trailing_zeros(),
            }
        } else {
            ScaleOp::Multiply { delta }
        };
        Self { op }
    }

    /// Scales a magnitude whose mathematical product `m*delta` is below `q`.
    #[inline]
    pub(super) fn encode_magnitude(&self, m: T) -> T {
        match self.op {
            ScaleOp::Shift { shift } => m << shift,
            ScaleOp::Multiply { delta } => m * delta,
        }
    }

    /// Negates a nonzero canonical encoding modulo `q`.
    ///
    /// # Correctness
    ///
    /// Requires `0 < value < q`. Negative lifts have positive magnitude and
    /// the scale invariant ensures their encodings satisfy this condition.
    #[inline]
    pub(super) fn neg_nonzero<M>(&self, value: T, modulus: M) -> T
    where
        M: Modulus<ValueT = T>,
    {
        // q-1 is representable for every modulus; nonzero input keeps both operations in range.
        debug_assert!(value != T::ZERO);
        modulus.minus_one() - value + T::ONE
    }

    /// Applies scaling to validated messages, optionally adding to canonical output.
    /// The iterator also permits in-place encoding without allocating a copy.
    ///
    /// # Correctness
    ///
    /// `t` must satisfy the scale invariant established by the owning codec.
    /// Each message must be in `[0,t)`; when `ADD` is true, each output must
    /// already be in `[0,q)`. These preconditions are not checked here.
    // Keep dispatch inline so callers can specialize the scale and modulus.
    #[inline(always)]
    pub(super) fn apply<'a, const ADD: bool, I, M>(
        &self,
        input: I,
        t: T,
        embedding: PlaintextEmbedding,
        modulus: M,
    ) where
        I: Iterator<Item = (&'a mut T, T)>,
        T: 'a,
        M: Modulus<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let neg = |x| modulus.minus_one() - x + T::ONE;
        let add = |a, b| modulus.reduce_add(a, b);
        match self.op {
            ScaleOp::Shift { shift } => {
                apply_kernel::<T, ADD, _, _, _, _>(input, t, embedding, |m| m << shift, neg, add);
            }
            ScaleOp::Multiply { delta } => {
                apply_kernel::<T, ADD, _, _, _, _>(input, t, embedding, |m| m * delta, neg, add);
            }
        }
    }
}

/// Modulus, scale and embedding dispatch is performed before entering the loop.
/// Inherits the validated message and accumulator ranges from `IntegerScale::apply`.
/// The positive scale makes encodings of negative lifts nonzero, so `neg` may
/// use `q - value` directly for explicit moduli.
#[inline]
fn apply_kernel<'a, T, const ADD: bool, I, E, N, A>(
    input: I,
    t: T,
    embedding: PlaintextEmbedding,
    encode: E,
    neg: N,
    add: A,
) where
    I: Iterator<Item = (&'a mut T, T)>,
    E: Fn(T) -> T,
    N: Fn(T) -> T,
    A: Fn(T, T) -> T,
    T: FheUint + 'a,
{
    match embedding {
        PlaintextEmbedding::Unsigned => {
            for (out, m) in input {
                let value = encode(m);
                *out = if ADD { add(*out, value) } else { value };
            }
        }
        PlaintextEmbedding::Centered => {
            let negative_start = centered_negative_start(t);
            for (out, m) in input {
                let (magnitude, negative) = lift_centered_from_raw(m, t, negative_start);
                let value = encode(magnitude);
                let value = if negative { neg(value) } else { value };
                *out = if ADD { add(*out, value) } else { value };
            }
        }
    }
}
