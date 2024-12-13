use algebra::{
    reduce::{AddReduceOps, MulReduceOps, SubReduceOps},
    AddOps, SubOps,
};

///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmLwe<T> {
    a: Vec<T>,
    b: Vec<T>,
}

impl<T> CmLwe<T> {
    /// Creates a new [`CmLwe<T>`].
    #[inline]
    pub fn new(a: Vec<T>, b: Vec<T>) -> Self {
        Self { a, b }
    }

    /// Returns a reference to the a of this [`CmLwe<T>`].
    pub fn a(&self) -> &[T] {
        &self.a
    }

    /// Returns a reference to the b of this [`CmLwe<T>`].
    pub fn b(&self) -> &[T] {
        &self.b
    }

    /// Returns a mutable reference to the a of this [`CmLwe<T>`].
    pub fn a_mut(&mut self) -> &mut Vec<T> {
        &mut self.a
    }

    /// Returns a mutable reference to the b of this [`CmLwe<T>`].
    pub fn b_mut(&mut self) -> &mut Vec<T> {
        &mut self.b
    }
}

impl<T: AddOps> CmLwe<T> {
    ///
    #[inline]
    pub fn add_component_wise_ref(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.b.len(), rhs.b.len());
        Self::new(
            self.a.iter().zip(rhs.a()).map(|(&x, &y)| x + y).collect(),
            self.b.iter().zip(rhs.b()).map(|(&x, &y)| x + y).collect(),
        )
    }

    ///
    #[inline]
    pub fn add_component_wise(mut self, rhs: &Self) -> Self {
        self.add_component_wise_assign(rhs);
        self
    }

    ///
    #[inline]
    pub fn add_component_wise_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.b.len(), rhs.b.len());
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| *v0 += v1);
        self.b
            .iter_mut()
            .zip(rhs.b())
            .for_each(|(v0, &v1)| *v0 += v1);
    }
}

impl<T: SubOps> CmLwe<T> {
    ///
    #[inline]
    pub fn sub_component_wise_ref(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a.iter().zip(rhs.a()).map(|(&x, &y)| x - y).collect(),
            self.b.iter().zip(rhs.b()).map(|(&x, &y)| x - y).collect(),
        )
    }

    ///
    #[inline]
    pub fn sub_component_wise(mut self, rhs: &Self) -> Self {
        self.sub_component_wise_assign(rhs);
        self
    }

    ///
    #[inline]
    pub fn sub_component_wise_assign(&mut self, rhs: &Self) {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| *v0 -= v1);
        self.b
            .iter_mut()
            .zip(rhs.b())
            .for_each(|(v0, &v1)| *v0 -= v1);
    }
}

impl<T> CmLwe<T> {
    ///
    #[inline]
    pub fn add_reduce_component_wise_ref<M>(&self, rhs: &Self, modulus: M) -> Self
    where
        T: AddReduceOps<M>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&x, &y)| x.add_reduce(y, modulus))
                .collect(),
            self.b
                .iter()
                .zip(rhs.b())
                .map(|(&x, &y)| x.add_reduce(y, modulus))
                .collect(),
        )
    }

    ///
    #[inline]
    pub fn add_reduce_component_wise<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        T: AddReduceOps<M>,
        M: Copy,
    {
        self.add_reduce_component_wise_assign(rhs, modulus);
        self
    }

    ///
    #[inline]
    pub fn add_reduce_component_wise_assign<M>(&mut self, rhs: &Self, modulus: M)
    where
        T: AddReduceOps<M>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        debug_assert_eq!(self.b.len(), rhs.b.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| v0.add_reduce_assign(v1, modulus));
        self.b
            .iter_mut()
            .zip(rhs.b())
            .for_each(|(v0, &v1)| v0.add_reduce_assign(v1, modulus));
    }

    ///
    #[inline]
    pub fn sub_reduce_component_wise_ref<M>(&self, rhs: &Self, modulus: M) -> Self
    where
        T: SubReduceOps<M>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        Self::new(
            self.a
                .iter()
                .zip(rhs.a())
                .map(|(&x, &y)| x.sub_reduce(y, modulus))
                .collect(),
            self.b
                .iter()
                .zip(rhs.b())
                .map(|(&x, &y)| x.sub_reduce(y, modulus))
                .collect(),
        )
    }

    ///
    #[inline]
    pub fn sub_reduce_component_wise<M>(mut self, rhs: &Self, modulus: M) -> Self
    where
        T: SubReduceOps<M>,
        M: Copy,
    {
        self.sub_reduce_component_wise_assign(rhs, modulus);
        self
    }

    ///
    #[inline]
    pub fn sub_reduce_component_wise_assign<M>(&mut self, rhs: &Self, modulus: M)
    where
        T: SubReduceOps<M>,
        M: Copy,
    {
        debug_assert_eq!(self.a.len(), rhs.a.len());
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v0, &v1)| v0.sub_reduce_assign(v1, modulus));
        self.b
            .iter_mut()
            .zip(rhs.b())
            .for_each(|(v0, &v1)| v0.sub_reduce_assign(v1, modulus));
    }

    ///
    #[inline]
    pub fn scalar_mul_reduce_inplace<M>(&mut self, scalar: T, modulus: M)
    where
        T: MulReduceOps<M>,
        M: Copy,
    {
        self.a
            .iter_mut()
            .for_each(|v| v.mul_reduce_assign(scalar, modulus));
        self.b
            .iter_mut()
            .for_each(|v| v.mul_reduce_assign(scalar, modulus));
    }

    ///
    #[inline]
    pub fn add_assign_rhs_mul_scalar_reduce<M>(&mut self, rhs: &Self, scalar: T, modulus: M)
    where
        T: MulReduceOps<M> + AddReduceOps<M>,
        M: Copy,
    {
        self.a
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v, r)| v.add_reduce_assign(r.mul_reduce(scalar, modulus), modulus));
        self.b
            .iter_mut()
            .zip(rhs.a())
            .for_each(|(v, r)| v.add_reduce_assign(r.mul_reduce(scalar, modulus), modulus));
    }
}
