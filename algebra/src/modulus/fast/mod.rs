//! <https://arxiv.org/abs/1902.01961>
//! <https://lemire.me/blog/2019/02/08/faster-remainders-when-the-divisor-is-a-constant-beating-compilers-and-libdivide/>
//! <https://lemire.me/blog/2019/02/20/more-fun-with-fast-remainders-when-the-divisor-is-a-constant/>

use crate::numeric::Numeric;

#[macro_use]
mod macros;
mod ops;

#[derive(Debug, Clone, Copy)]
pub struct FastModulus<T: Numeric> {
    value: T,
    ratio: [T; 2],
    // TODO: wide_ratio: [T; 4],
}

impl_fast_modulus!(impl FastModulus<u8>; WideType: u16);
impl_fast_modulus!(impl FastModulus<u16>; WideType: u32);
impl_fast_modulus!(impl FastModulus<u32>; WideType: u64);
impl_fast_modulus!(impl FastModulus<u64>; WideType: u128);

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use rand_distr::Standard;

    use crate::reduce::Reduce;

    use super::*;

    type ValueT = u16;
    // type WideT = <ValueT as Numeric>::WideT;

    #[test]
    fn test_reduce() {
        let mut rng = thread_rng();
        let modulus_value = rng.gen_range(2..ValueT::MAX);
        let modulus = <FastModulus<ValueT>>::new(modulus_value);

        for value in (&mut rng).sample_iter::<ValueT, _>(Standard).take(1000000) {
            assert_eq!(modulus.reduce(value), value % modulus_value);
        }

        // for value in (&mut rng)
        //     .sample_iter::<[ValueT; 2], _>(Standard)
        //     .take(1000000)
        // {
        //     let rem = ((value[0] as WideT + ((value[1] as WideT) << ValueT::BITS))
        //         % (modulus_value as WideT)) as ValueT;
        //     assert_eq!(modulus.reduce(value), rem);
        // }
    }
}
