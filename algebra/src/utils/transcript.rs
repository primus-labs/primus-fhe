use std::marker::PhantomData;

use rand::SeedableRng;
use rand_distr::Distribution;
use serde::Serialize;

use crate::{AbstractExtensionField, Field, FieldUniformSampler};

use super::{Block, Prg};

/// A transcript consists of a Merlin transcript and a `sampler``
/// to sample uniform field elements.
pub struct Transcript<F: Field> {
    transcript: merlin::Transcript,
    sampler: FieldUniformSampler<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> Transcript<F> {
    /// Create a new IOP transcript.
    #[inline]
    pub fn new() -> Self {
        Self {
            transcript: merlin::Transcript::new(b""),
            sampler: FieldUniformSampler::new(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Transcript<F> {
    /// Append the message to the transcript.
    pub fn append_message<M: Serialize>(&mut self, label: &'static [u8], msg: &M) {
        self.transcript
            .append_message(label, &bincode::serialize(msg).unwrap());
    }

    /// Generate the challenge bytes from the current transcript
    #[inline]
    pub fn get_challenge_bytes(&mut self, label: &'static [u8], bytes: &mut [u8]) {
        self.transcript.challenge_bytes(label, bytes);
    }

    /// Generate the challenge from the current transcript
    pub fn get_challenge(&mut self, label: &'static [u8]) -> F {
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        F::random(&mut prg)
        // self.sampler.sample(&mut prg)
    }

    /// Generate the challenge vector from the current transcript
    pub fn get_vec_challenge(&mut self, label: &'static [u8], num: usize) -> Vec<F> {
        let mut seed = [0u8; 16];
        self.transcript.challenge_bytes(label, &mut seed);
        let mut prg = Prg::from_seed(Block::from(seed));
        let w = F::random(&mut prg);
        (0..num).into_iter().map(|_| F::random(&mut prg)).collect()
        // self.sampler.sample_iter(&mut prg).take(num).collect()
    }

    /// Generate the challenge for extension field from the current transcript
    #[inline]
    pub fn get_ext_field_challenge<EF>(&mut self, label: &'static [u8]) -> EF
    where
        EF: AbstractExtensionField<F>,
    {
        let value = self.get_vec_challenge(label, EF::D);
        EF::from_base_slice(&value)
    }

    /// Generate the challenge vector for extension field from the current transcript
    #[inline]
    pub fn get_vec_ext_field_challenge<EF>(&mut self, label: &'static [u8], num: usize) -> Vec<EF>
    where
        EF: AbstractExtensionField<F>,
    {
        let challenges = self.get_vec_challenge(label, num * EF::D);
        challenges
            .chunks_exact(EF::D)
            .map(|ext| EF::from_base_slice(ext))
            .collect()
    }
}

impl<F: Field> Default for Transcript<F> {
    fn default() -> Self {
        Self::new()
    }
}
