//! Source-specific modulus-switch preparation; execution lives in primus_reduce.
use crate::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_integer::FheUint;
use primus_reduce::{Modulus, ModulusSwitch, PrepareModulusSwitch};

macro_rules! impl_prepare {
    ($($modulus:ident),+ $(,)?) => {$(
        impl<T: FheUint> PrepareModulusSwitch for $modulus<T> {
            #[inline]
            fn prepare_switch_to<D: Modulus<ValueT = T>>(self, target: D) -> ModulusSwitch<T> {
                ModulusSwitch::new(self, target)
            }
        }
    )+};
}
impl_prepare!(NativeModulus, PowOf2Modulus, UintModulus, CompactModulus);

impl<T: FheUint> PrepareModulusSwitch for BarrettModulus<T> {
    #[inline]
    fn prepare_switch_to<D: Modulus<ValueT = T>>(self, target: D) -> ModulusSwitch<T> {
        ModulusSwitch::with_source_reciprocal(self.value(), target, self.ratio())
    }
}
