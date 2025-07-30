use std::{slice::ChunksExact, sync::Arc};

use algebra::{
    decompose::{NonPowOf2ApproxSignedBasis, PowOf2ApproxSignedBasis},
    integer::UnsignedInteger,
    ntt::NttTable,
    polynomial::{FieldNttPolynomial, FieldPolynomial},
    reduce::{ReduceNegAssign, RingReduce},
    utils::Size,
    Field, NttField,
};
use lattice::{utils::PolyDecomposeSpace, Lwe, NttGadgetRlwe, NttRlwe};
use num_traits::ConstOne;
use rand::{CryptoRng, Rng};

use crate::{
    utils::Pool, KeySwitchingParameters, LweCiphertext, LweSecretKey, NttRlweSecretKey,
    RlweCiphertext, RlweSecretKey,
};

/// The Key Switching Key.
///
/// This struct stores the key that switch a ciphertext of the another secret key
/// to a [`Lwe<C>`] ciphertext.
#[derive(Clone)]
pub struct PowOf2LweKeySwitchingKey<C: UnsignedInteger> {
    /// Key Switching Key data
    ///
    /// k_{i, j}
    ///
    /// i \in \{0, dks-1\}
    /// j \in \{0, N-1\}
    key: Vec<Vec<Lwe<C>>>,
    /// Key Switching Key parameters
    params: KeySwitchingParameters,
    /// Basis for the key switching
    basis: PowOf2ApproxSignedBasis<C>,
    space: Pool<(Vec<C>, Vec<bool>)>,
}

impl<C: UnsignedInteger> PowOf2LweKeySwitchingKey<C> {
    /// Generates a new [`PowOf2LweKeySwitchingKey<C>`].
    pub fn generate<CIn, R>(
        s_in: &LweSecretKey<CIn>,
        s_out: &LweSecretKey<C>,
        key_switching_key_params: KeySwitchingParameters,
        modulus: impl RingReduce<C>,
        rng: &mut R,
    ) -> Self
    where
        CIn: UnsignedInteger,
        R: Rng + CryptoRng,
    {
        let log_modulus = key_switching_key_params.log_modulus;
        let minus_one = modulus.modulus_minus_one();
        let basis = PowOf2ApproxSignedBasis::new(
            log_modulus,
            key_switching_key_params.log_basis,
            key_switching_key_params.reverse_length,
        );
        let gaussian = key_switching_key_params.noise_distribution_for_q(minus_one);

        let convert = |v: &CIn| {
            if v.is_zero() {
                C::ZERO
            } else if v.is_one() {
                C::ONE
            } else {
                minus_one
            }
        };

        let s_in_vec: Vec<C> = s_in.as_ref().iter().map(convert).collect();

        let key: Vec<Vec<Lwe<C>>> = basis
            .scalar_iter()
            .map(|scalar| {
                let inner: Vec<Lwe<C>> = s_in_vec
                    .iter()
                    .map(|&s_in_j| {
                        let mut cipher = <Lwe<C>>::generate_random_zero_sample(
                            s_out.as_ref(),
                            modulus,
                            gaussian,
                            rng,
                        );

                        modulus
                            .reduce_add_assign(cipher.b_mut(), modulus.reduce_mul(s_in_j, scalar));

                        cipher
                    })
                    .collect();

                inner
            })
            .collect();

        Self {
            key,
            params: key_switching_key_params,
            basis,
            space: Pool::new(),
        }
    }

    /// Performs key switching operation.
    pub fn key_switch(
        &self,
        ciphertext: &LweCiphertext<C>,
        modulus: impl RingReduce<C>,
    ) -> LweCiphertext<C> {
        let dimension = self.params.output_cipher_dimension;
        let minus_one = modulus.modulus_minus_one();

        let a = ciphertext.a();

        let mut result = <Lwe<C>>::zero(dimension);

        let (mut decomposed, mut carries) = match self.space.get() {
            Some(sp) => sp,
            None => (vec![C::ZERO; a.len()], vec![false; a.len()]),
        };

        self.basis.init_carry_slice(a, &mut carries);

        self.key
            .iter()
            .zip(self.basis.decompose_iter())
            .for_each(|(key_i, once_decompose)| {
                once_decompose.decompose_slice_inplace(a, &mut carries, decomposed.as_mut_slice());
                decomposed.iter().zip(key_i).for_each(|(&d_i, s_i)| {
                    if !d_i.is_zero() {
                        if d_i.is_one() {
                            result.add_reduce_assign_component_wise(s_i, modulus);
                        } else if d_i == minus_one {
                            result.sub_reduce_assign_component_wise(s_i, modulus);
                        } else {
                            result.add_assign_rhs_mul_scalar_reduce(s_i, d_i, modulus);
                        }
                    }
                });
            });

        self.space.store((decomposed, carries));

        result.neg_reduce_assign(modulus);
        modulus.reduce_add_assign(result.b_mut(), ciphertext.b());

        result
    }
}

impl<C: UnsignedInteger> Size for PowOf2LweKeySwitchingKey<C> {
    #[inline]
    fn size(&self) -> usize {
        if self.key.is_empty() || self.key[0].is_empty() {
            return 0;
        }
        self.key.len() * self.key[0].len() * self.key[0][0].size()
    }
}

/// The Key Switching Key.
///
/// This struct stores the key that switch a ciphertext of the another secret key
/// to a [`Lwe<C>`] ciphertext.
#[derive(Clone)]
pub struct NonPowOf2LweKeySwitchingKey<C: UnsignedInteger> {
    /// Key Switching Key data
    ///
    /// k_{i, j}
    ///
    /// i \in \{0, dks-1\}
    /// j \in \{0, N-1\}
    key: Vec<Vec<Lwe<C>>>,
    params: KeySwitchingParameters,
    basis: NonPowOf2ApproxSignedBasis<C>,
    space: Pool<(Vec<C>, Vec<C>, Vec<bool>)>,
}

impl<C: UnsignedInteger> NonPowOf2LweKeySwitchingKey<C> {
    /// Creates a new [`NonPowOf2LweKeySwitchingKey<C>`].
    #[inline]
    pub fn new(
        key: Vec<Vec<Lwe<C>>>,
        params: KeySwitchingParameters,
        basis: NonPowOf2ApproxSignedBasis<C>,
    ) -> Self {
        Self {
            key,
            params,
            basis,
            space: Pool::new(),
        }
    }

    /// Generates a new [`NonPowOf2LweKeySwitchingKey<C>`].
    pub fn generate<COut, R>(
        s_in: &LweSecretKey<C>,
        s_out: &LweSecretKey<COut>,
        key_switching_key_params: KeySwitchingParameters,
        modulus: impl RingReduce<C>,
        rng: &mut R,
    ) -> Self
    where
        COut: UnsignedInteger,
        R: Rng + CryptoRng,
    {
        let minus_one = modulus.modulus_minus_one();
        let basis = NonPowOf2ApproxSignedBasis::new(
            minus_one + <C as ConstOne>::ONE,
            key_switching_key_params.log_basis,
            key_switching_key_params.reverse_length,
        );
        let gaussian = key_switching_key_params.noise_distribution_for_q(minus_one);

        let convert = |v: &COut| {
            if v.is_zero() {
                C::ZERO
            } else if v.is_one() {
                C::ONE
            } else {
                minus_one
            }
        };

        let s_out_vec: Vec<C> = s_out.as_ref().iter().map(convert).collect();

        let key: Vec<Vec<Lwe<C>>> = basis
            .scalar_iter()
            .map(|scalar| {
                s_in.as_ref()
                    .iter()
                    .map(|&s_in_j| {
                        let mut cipher = <Lwe<C>>::generate_random_zero_sample(
                            s_out_vec.as_ref(),
                            modulus,
                            gaussian,
                            rng,
                        );

                        modulus
                            .reduce_add_assign(cipher.b_mut(), modulus.reduce_mul(s_in_j, scalar));

                        cipher
                    })
                    .collect::<Vec<Lwe<C>>>()
            })
            .collect();

        Self {
            key,
            params: key_switching_key_params,
            basis,
            space: Pool::new(),
        }
    }

    /// Performs key switching operation.
    pub fn key_switch(
        &self,
        ciphertext: &LweCiphertext<C>,
        modulus: impl RingReduce<C>,
    ) -> LweCiphertext<C> {
        let dimension = self.params.output_cipher_dimension;
        let minus_one = modulus.modulus_minus_one();

        let a = ciphertext.a();

        let mut result = <Lwe<C>>::zero(dimension);

        let (mut adjust_values, mut decomposed, mut carries) = match self.space.get() {
            Some(sp) => sp,
            None => (
                vec![C::ZERO; a.len()],
                vec![C::ZERO; a.len()],
                vec![false; a.len()],
            ),
        };

        self.basis
            .init_value_carry_slice(a, &mut carries, &mut adjust_values);

        self.key
            .iter()
            .zip(self.basis.decompose_iter())
            .for_each(|(key_i, once_decompose)| {
                once_decompose.decompose_slice_inplace(
                    &adjust_values,
                    &mut carries,
                    decomposed.as_mut_slice(),
                );
                decomposed.iter().zip(key_i).for_each(|(&d_i, s_i)| {
                    if !d_i.is_zero() {
                        if d_i.is_one() {
                            result.add_reduce_assign_component_wise(s_i, modulus);
                        } else if d_i == minus_one {
                            result.sub_reduce_assign_component_wise(s_i, modulus);
                        } else {
                            result.add_assign_rhs_mul_scalar_reduce(s_i, d_i, modulus);
                        }
                    }
                });
            });

        self.space.store((adjust_values, decomposed, carries));

        result.neg_reduce_assign(modulus);
        modulus.reduce_add_assign(result.b_mut(), ciphertext.b());

        result
    }
}

impl<C: UnsignedInteger> Size for NonPowOf2LweKeySwitchingKey<C> {
    #[inline]
    fn size(&self) -> usize {
        if self.key.is_empty() || self.key[0].is_empty() {
            return 0;
        }
        self.key.len() * self.key[0].len() * self.key[0][0].size()
    }
}

/// Represents a key switching key for the RLWE mode in the Learning with Errors (LWE) cryptographic scheme.
///
/// # Type Parameters
///
/// * `Q` - A field that supports Number Theoretic Transform (NTT) operations.
#[derive(Clone)]
pub struct LweKeySwitchingKeyRlweMode<Q: NttField> {
    key: Vec<NttGadgetRlwe<Q>>,
    key_switching_key_params: KeySwitchingParameters,
    ntt_table: Arc<<Q as NttField>::Table>,
    space: Pool<(PolyDecomposeSpace<Q>, FieldPolynomial<Q>)>,
}

impl<Q: NttField> LweKeySwitchingKeyRlweMode<Q> {
    /// Generates a new `LweKeySwitchingKeyRlweMode` using the provided RLWE secret key, LWE secret key,
    /// key switching parameters, NTT table, and random number generator.
    ///
    /// # Arguments
    ///
    /// * `rlwe_secret_key` - A reference to the RLWE secret key.
    /// * `lwe_secret_key` - A reference to the LWE secret key.
    /// * `key_switching_key_params` - The parameters for the key switching key.
    /// * `ntt_table` - The NTT table used for Number Theoretic Transform operations.
    /// * `rng` - A mutable reference to a random number generator.
    ///
    /// # Returns
    ///
    /// A new instance of `LweKeySwitchingKeyRlweMode`.
    pub fn generate<C, R>(
        rlwe_secret_key: &RlweSecretKey<Q>,
        lwe_secret_key: &LweSecretKey<C>,
        key_switching_key_params: KeySwitchingParameters,
        ntt_table: Arc<<Q as NttField>::Table>,
        rng: &mut R,
    ) -> Self
    where
        C: UnsignedInteger,
        R: Rng + CryptoRng,
    {
        let rlwe_dimension = key_switching_key_params.input_cipher_dimension;
        let lwe_dimension = key_switching_key_params.output_cipher_dimension;
        assert!(lwe_dimension.is_power_of_two() && lwe_dimension <= rlwe_dimension);

        let ntt_table = if ntt_table.dimension() == lwe_dimension {
            ntt_table
        } else {
            Arc::new(Q::generate_ntt_table(lwe_dimension.trailing_zeros()).unwrap())
        };

        let gaussian = key_switching_key_params.noise_distribution_for_Q::<Q>();

        let key_switching_basis = NonPowOf2ApproxSignedBasis::new(
            Q::MODULUS_VALUE,
            key_switching_key_params.log_basis,
            key_switching_key_params.reverse_length,
        );

        let lwe_secret_key = <RlweSecretKey<Q>>::from_lwe_secret_key(lwe_secret_key);
        let lwe_secret_key = NttRlweSecretKey::from_coeff_secret_key(&lwe_secret_key, &ntt_table);

        let rlwe_secret_key_chunks: Vec<FieldPolynomial<Q>> = rlwe_secret_key
            .as_slice()
            .chunks_exact(lwe_dimension)
            .map(|part| FieldPolynomial::from_slice(part))
            .collect();

        let key = rlwe_secret_key_chunks
            .into_iter()
            .map(|rlwe_secret_key_chunk| {
                let ntt_rlwe_secret_key_chunks = rlwe_secret_key_chunk.into_ntt_poly(&ntt_table);
                NttGadgetRlwe::generate_random_poly_sample(
                    &lwe_secret_key,
                    &ntt_rlwe_secret_key_chunks,
                    &key_switching_basis,
                    gaussian,
                    &ntt_table,
                    rng,
                )
            })
            .collect();

        Self {
            key,
            key_switching_key_params,
            ntt_table,
            space: Pool::new(),
        }
    }

    /// Performs key switching operation.
    pub fn key_switch_for_rlwe(
        &self,
        mut ciphertext: RlweCiphertext<Q>,
    ) -> LweCiphertext<<Q as Field>::ValueT> {
        let lwe_dimension = self.key_switching_key_params.output_cipher_dimension;
        let b = ciphertext.b()[0];
        let init = <NttRlwe<Q>>::new(
            FieldNttPolynomial::zero(lwe_dimension),
            FieldNttPolynomial::new(vec![b; lwe_dimension]),
        );

        if ciphertext.dimension() != lwe_dimension {
            let a = ciphertext.a_mut_slice();
            Q::MODULUS.reduce_neg_assign(&mut a[0]);
            a[1..].reverse();
            a.chunks_exact_mut(lwe_dimension).for_each(|chunk| {
                Q::MODULUS.reduce_neg_assign(&mut chunk[0]);
                chunk[1..].reverse();
            });
        }

        let iter = ciphertext.a_slice().chunks_exact(lwe_dimension);

        self.key_switch_inner(lwe_dimension, init, iter)
    }

    /// Performs key switching operation.
    pub fn key_switch_for_lwe(
        &self,
        mut ciphertext: LweCiphertext<<Q as Field>::ValueT>,
    ) -> LweCiphertext<<Q as Field>::ValueT> {
        let lwe_dimension = self.key_switching_key_params.output_cipher_dimension;
        let b = ciphertext.b();
        let init = <NttRlwe<Q>>::new(
            FieldNttPolynomial::zero(lwe_dimension),
            FieldNttPolynomial::new(vec![b; lwe_dimension]),
        );

        let a = ciphertext.a_mut_slice();
        a.chunks_exact_mut(lwe_dimension).for_each(|chunk| {
            chunk[1..].reverse();
            chunk[1..]
                .iter_mut()
                .for_each(|v| Q::MODULUS.reduce_neg_assign(v))
        });

        let iter = ciphertext.a_slice().chunks_exact(lwe_dimension);

        self.key_switch_inner(lwe_dimension, init, iter)
    }

    fn key_switch_inner(
        &self,
        lwe_dimension: usize,
        mut init: NttRlwe<Q>,
        iter: ChunksExact<<Q as Field>::ValueT>,
    ) -> LweCiphertext<<Q as Field>::ValueT> {
        let ntt_table = self.ntt_table.as_ref();
        let (mut decompose_space, mut poly_space) = match self.space.get() {
            Some(sp) => sp,
            None => (
                PolyDecomposeSpace::new(lwe_dimension),
                FieldPolynomial::zero(lwe_dimension),
            ),
        };

        self.key.iter().zip(iter).for_each(
            |(z_i, a_i): (&NttGadgetRlwe<Q>, &[<Q as Field>::ValueT])| {
                poly_space.copy_from(a_i);
                init.sub_assign_gadget_rlwe_mul_polynomial_fast(
                    z_i,
                    &poly_space,
                    ntt_table,
                    &mut decompose_space,
                );
            },
        );

        self.space.store((decompose_space, poly_space));

        init.to_rlwe(ntt_table).extract_lwe_locally()
    }
}

impl<Q: NttField> Size for LweKeySwitchingKeyRlweMode<Q> {
    #[inline]
    fn size(&self) -> usize {
        if self.key.is_empty() {
            return 0;
        }
        self.key.len() * self.key[0].size()
    }
}
