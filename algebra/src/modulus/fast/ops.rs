use crate::{numeric::Numeric, reduce::*};

use super::FastModulus;

impl<T: Numeric> Reduce<T> for FastModulus<T> {
    type Output = T;

    #[inline]
    fn reduce(self, value: T) -> Self::Output {
        // Step 1.
        //              ratio[1]  ratio[0]
        //         *               value
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //            +-------------------+
        //            |  tmp1   |         |    <-- value * ratio[0]
        //            +-------------------+
        //   +------------------+
        //   |      tmp2        |              <-- value * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //   +--------+
        //   |   q₃   |
        //   +--------+
        let tmp = value.widening_mul_hw(self.ratio[0]); // tmp1
        let q = value.carrying_mul_hw(self.ratio[1], tmp); // q₃

        value - q * self.value
    }
}

// impl<T: Numeric> Reduce<[T; 2]> for FastModulus<T> {
//     type Output = T;

//     #[inline]
//     fn reduce(self, value: [T; 2]) -> Self::Output {
//         // Step 1.
//         //                        ratio[1]  ratio[0]
//         //                   *    value[1]  value[0]
//         //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//         //                      +-------------------+
//         //                      |         a         |    <-- value[0] * ratio[0]
//         //                      +-------------------+
//         //             +------------------+
//         //             |        b         |              <-- value[0] * ratio[1]
//         //             +------------------+
//         //             +------------------+
//         //             |        c         |              <-- value[1] * ratio[0]
//         //             +------------------+
//         //   +------------------+
//         //   |        d         |                        <-- value[1] * ratio[1]
//         //   +------------------+
//         //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//         //             +--------+
//         //             |   q₃   |
//         //             +--------+
//         let ah = value[0].widening_mul_hw(self.ratio[0]);

//         let b = value[0].carrying_mul(self.ratio[1], ah);
//         let c = value[1].widening_mul(self.ratio[0]);

//         let d = value[1].wrapping_mul(self.ratio[1]);

//         let bch = b.1 + c.1 + b.0.overflowing_add(c.0).1.as_into();

//         let q = d.wrapping_add(bch);

//         // Step 2.
//         value[0].wrapping_sub(q.wrapping_mul(self.value))
//     }
// }

impl<T: Numeric> ReduceAssign<T> for FastModulus<T> {
    #[inline]
    fn reduce_assign(self, value: &mut T) {
        *value = self.reduce(*value);
    }
}

impl<T: Numeric> ReduceOnce<T> for FastModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_once(self, value: T) -> Self::Output {
        self.value.reduce_once(value)
    }
}

impl<T: Numeric> ReduceOnceAssign<T> for FastModulus<T> {
    #[inline(always)]
    fn reduce_once_assign(self, value: &mut T) {
        self.value.reduce_once_assign(value);
    }
}

impl<T: Numeric> ReduceAdd<T> for FastModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_add(self, a: T, b: T) -> Self::Output {
        self.value.reduce_add(a, b)
    }
}

impl<T: Numeric> ReduceAddAssign<T> for FastModulus<T> {
    #[inline(always)]
    fn reduce_add_assign(self, a: &mut T, b: T) {
        self.value.reduce_add_assign(a, b);
    }
}

impl<T: Numeric> ReduceDouble<T> for FastModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_double(self, value: T) -> Self::Output {
        self.value.reduce_double(value)
    }
}

impl<T: Numeric> ReduceDoubleAssign<T> for FastModulus<T> {
    #[inline(always)]
    fn reduce_double_assign(self, value: &mut T) {
        self.value.reduce_double_assign(value);
    }
}

impl<T: Numeric> ReduceSub<T> for FastModulus<T> {
    type Output = T;

    #[inline(always)]
    fn reduce_sub(self, a: T, b: T) -> Self::Output {
        self.value.reduce_sub(a, b)
    }
}

impl<T: Numeric> ReduceSubAssign<T> for FastModulus<T> {
    #[inline(always)]
    fn reduce_sub_assign(self, a: &mut T, b: T) {
        self.value.reduce_sub_assign(a, b);
    }
}
