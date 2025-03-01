use algebra::{polynomial::FieldPolynomial, Field};
use fhe_core::{
    lwe_modulus_switch_assign, BinaryBlindRotationKey, LweCiphertext, NonPowOf2LweKeySwitchingKey,
};
use itertools::Itertools;

use crate::{Fp, ThFheParameters};

/// The evaluator of the homomorphic encryption scheme.
#[derive(Clone)]
pub struct EvaluationKey {
    /// Key switching key.
    key_switching_key: NonPowOf2LweKeySwitchingKey<<Fp as Field>::ValueT>,
    /// Blind rotation key.
    blind_rotation_key: BinaryBlindRotationKey<Fp>,
    /// The parameters of the fully homomorphic encryption scheme.
    parameters: ThFheParameters,
}

impl EvaluationKey {
    /// Creates a new [`EvaluationKey`].
    #[inline]
    pub fn new(
        key_switching_key: NonPowOf2LweKeySwitchingKey<<Fp as Field>::ValueT>,
        blind_rotation_key: BinaryBlindRotationKey<Fp>,
        parameters: ThFheParameters,
    ) -> Self {
        Self {
            key_switching_key,
            blind_rotation_key,
            parameters,
        }
    }

    /// Returns the parameters of this [`EvaluationKey`].
    #[inline]
    pub fn parameters(&self) -> ThFheParameters {
        self.parameters
    }

    /// Complete the bootstrapping operation with LWE Ciphertext *`c`* and lookup table `lut`.
    pub fn bootstrap(
        &self,
        c: &LweCiphertext<u64>,
        lut: FieldPolynomial<Fp>,
    ) -> LweCiphertext<u64> {
        let parameters = self.parameters();

        let mut c = self
            .key_switching_key
            .key_switch(c, parameters.input_lwe_cipher_modulus());

        lwe_modulus_switch_assign(
            &mut c,
            parameters.input_lwe_cipher_modulus_value(),
            parameters.ring_dimension() as u64 * 2,
        );

        let acc = self.blind_rotation_key.blind_rotate(lut, &c);

        acc.extract_lwe_locally()
    }
}

/// Evaluator
#[derive(Clone)]
pub struct Evaluator {
    ek: EvaluationKey,
}

impl Evaluator {
    /// Creates a new [`Evaluator`].
    #[inline]
    pub fn new(ek: EvaluationKey) -> Self {
        Self { ek }
    }

    /// Returns a reference to the parameters of this [`Evaluator`].
    #[inline]
    pub fn parameters(&self) -> &ThFheParameters {
        &self.ek.parameters
    }

    #[inline]
    pub fn add(&self, a: &LweCiphertext<u64>, b: &LweCiphertext<u64>) -> LweCiphertext<u64> {
        let parameters = self.parameters();
        let cipher_modulus = parameters.input_lwe_cipher_modulus();

        let add = a.add_reduce_component_wise_ref(b, cipher_modulus);

        let lut = add_lut(
            parameters.ring_dimension(),
            parameters.lwe_plain_modulus() as usize,
        );

        self.ek.bootstrap(&add, lut)
    }
}

fn add_lut(rlwe_dimension: usize, plain_modulus: usize) -> FieldPolynomial<Fp> {
    let q = Fp::MODULUS_VALUE;
    let delta: u64 = q / plain_modulus as u64;

    let log_plain_modulus = plain_modulus.trailing_zeros();
    let half_chunk = rlwe_dimension >> log_plain_modulus;

    let mut lut = <FieldPolynomial<Fp>>::zero(rlwe_dimension);

    let double = delta << 1;
    let triple = delta + double;

    let temp = [0, delta, double, triple, 0, delta, double, triple];
    let mut temp2 = temp;
    temp2.rotate_left(1);

    lut.as_mut_slice()
        .chunks_mut(half_chunk)
        .zip(temp.into_iter().interleave(temp2))
        .for_each(
            |(chunk, value): (&mut [<Fp as Field>::ValueT], <Fp as Field>::ValueT)| {
                chunk.fill(value);
            },
        );

    lut
}
