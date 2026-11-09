//! Shared-input and streamed NTRU returns through bounded LWE key-switch tiles.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lattice::lwe::{Lwe, LweIter, LweIterMut};
use primus_reduce::RingContext;
use primus_shape::PolyLength;

use super::NtruLweKeySwitchingKey;
use crate::NtruCiphertext;

// Match the LWE key-switch kernel's small tile without retaining all extracted
// samples. This bounds scratch independently of the caller's output count.
const RETURN_BATCH_SIZE: usize = 8;

impl<T: FheUint> NtruLweKeySwitchingKey<T> {
    /// Dimensions, the complete index sequence and q are already validated.
    /// Convert once for multiple outputs, keeping the converted polynomial live
    /// across tiles. A singleton uses fused conversion/extraction instead.
    pub(super) fn switch_shared_input<M, B>(
        &self,
        input: NtruCiphertext<&[T]>,
        mut indices: impl ExactSizeIterator<Item = usize>,
        outputs: &mut [Lwe<B>],
        modulus: M,
        workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        if outputs.is_empty() {
            return;
        }
        if outputs.len() == 1 {
            self.key_switch_coefficient(
                input,
                indices.next().expect("NTRU extraction index missing"),
                outputs[0].as_mut_view(),
                modulus,
                workspace.extracted_slot_mut(0),
            );
            return;
        }

        self.modulus_switch.switch_map(
            input
                .as_ref()
                .iter()
                .copied()
                .zip(workspace.converted.iter_mut()),
            |value, out| *out = value,
        );
        for outputs in outputs.chunks_mut(RETURN_BATCH_SIZE) {
            workspace.extract_converted_tile(&mut indices, outputs.len(), modulus);
            self.switch_extracted_tile(outputs, modulus, workspace);
        }
    }

    /// Validate the full extraction request before conversion or scratch writes.
    /// Consumes a cloned iterator so processing still starts at the original first index.
    pub(super) fn check_extraction(
        &self,
        input: NtruCiphertext<&[T]>,
        mut indices: impl ExactSizeIterator<Item = usize>,
        output_count: usize,
    ) {
        let n = self.poly_length();
        assert_eq!(input.as_ref().len(), n, "NTRU input length mismatch");
        assert_eq!(
            indices.len(),
            output_count,
            "NTRU extraction count mismatch"
        );
        assert!(
            indices.all(|index| index < n),
            "NTRU extraction index is out of range"
        );
    }

    /// Shared-input and streamed returns validate complete output/workspace
    /// shapes before writes; count/index checks belong to their distinct boundaries.
    pub(super) fn check_batch_outputs<B>(
        &self,
        outputs: &[Lwe<B>],
        workspace: &NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        B: Data<Elem = T>,
    {
        let output_len = self.output_dimension().ciphertext_len();
        assert!(
            outputs
                .iter()
                .all(|output| output.as_ref().len() == output_len),
            "target LWE ciphertext length mismatch"
        );
        assert_eq!(
            workspace.poly_length(),
            self.poly_length(),
            "NTRU to LWE workspace length mismatch"
        );
        assert_eq!(
            workspace.output_dimension(),
            self.output_dimension(),
            "NTRU to LWE workspace output dimension mismatch"
        );
    }

    /// The public boundary validated this tile. The singleton path avoids an
    /// intermediate output copy; larger tiles reuse the existing LWE batch kernel.
    pub(super) fn switch_extracted_tile<M, B>(
        &self,
        outputs: &mut [Lwe<B>],
        modulus: M,
        workspace: &mut NtruLweKeySwitchingBatchWorkspace<T>,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        let output_len = self.output_dimension().ciphertext_len();
        let (extracted, switched) = workspace.lwe_tiles_mut(outputs.len());
        match outputs {
            [] => {}
            [output] => self
                .key_switch
                .key_switch_to(&Lwe::new(extracted), output, modulus),
            _ => {
                self.key_switch
                    .key_switch_batch_to(extracted, switched, modulus);
                // The kernel writes a flat tile; callers own separate LWEs.
                for (output, sample) in outputs.iter_mut().zip(LweIter::new(switched, output_len)) {
                    output.as_mut().copy_from_slice(sample.as_ref());
                }
            }
        }
    }
}

/// Internal storage owned by [`super::LweReturnBatchWorkspace`].
///
/// Retains N converted coefficients and two tiles of eight LWEs: dimensions N
/// before key switching and `output_dimension` afterward. Storage is bounded
/// independently of the requested coefficient count and need not be cleared.
/// The owner tracks the valid prefix; the kernels only borrow complete tiles.
pub(super) struct NtruLweKeySwitchingBatchWorkspace<T: FheUint> {
    /// N coefficients at q, live across every tile of a shared-input return.
    /// Streamed preparation does not use this buffer.
    converted: Box<[T]>,
    /// Slot-major LWEs under f at q: each slot contains N mask values and a body.
    extracted: Box<[T]>,
    /// Flat target-key output tile, copied into the caller's separate LWE objects.
    /// Empty and singleton returns do not use this buffer.
    switched: Box<[T]>,
    output_dimension: LweDimension,
}

impl<T: FheUint> NtruLweKeySwitchingBatchWorkspace<T> {
    /// Allocates the converted polynomial and fixed input/output LWE tiles.
    ///
    /// # Panics
    /// Panics if a tile storage length overflows.
    #[must_use]
    pub(super) fn new(poly_length: PolyLength, output_dimension: LweDimension) -> Self {
        let input_dimension = LweDimension::from(poly_length);
        let poly_length = poly_length.get();
        let tile_len = |dimension: LweDimension| {
            dimension
                .ciphertext_len()
                .checked_mul(RETURN_BATCH_SIZE)
                .expect("NTRU to LWE batch workspace length overflow")
        };
        let extracted_len = tile_len(input_dimension);
        let switched_len = tile_len(output_dimension);
        Self {
            converted: vec![T::ZERO; poly_length].into_boxed_slice(),
            extracted: vec![T::ZERO; extracted_len].into_boxed_slice(),
            switched: vec![T::ZERO; switched_len].into_boxed_slice(),
            output_dimension,
        }
    }

    /// Returns the input NTRU polynomial length supported by this workspace.
    #[must_use]
    pub(super) fn poly_length(&self) -> usize {
        self.converted.len()
    }

    /// Returns the target LWE dimension supported by this workspace.
    #[must_use]
    fn output_dimension(&self) -> LweDimension {
        self.output_dimension
    }

    /// Maximum number of intermediate LWEs retained for one return tile.
    #[must_use]
    pub(super) const fn batch_capacity(&self) -> usize {
        RETURN_BATCH_SIZE
    }

    /// Borrows one complete intermediate LWE; the caller established slot < capacity.
    /// This alone does not mark the slot as part of a stream's valid prefix.
    #[must_use]
    pub(super) fn extracted_slot_mut(&mut self, slot: usize) -> Lwe<&mut [T]> {
        debug_assert!(slot < self.batch_capacity());
        let len = self.poly_length() + 1;
        // Construction checked capacity * len; the caller bounds the slot.
        let start = slot * len;
        Lwe::new(&mut self.extracted[start..start + len])
    }

    /// Fills one tile from the already rounded q-domain polynomial. The caller
    /// validated the complete index sequence and tile size; retaining `converted`
    /// across tiles avoids repeating Q→q. Extraction applies signs only afterward.
    fn extract_converted_tile<M: RingContext<T>>(
        &mut self,
        indices: &mut impl Iterator<Item = usize>,
        count: usize,
        modulus: M,
    ) {
        let sample_len = self.poly_length() + 1;
        let input = NtruCiphertext::new(&self.converted[..]);
        for mut sample in LweIterMut::new(&mut self.extracted[..count * sample_len], sample_len) {
            let index = indices.next().expect("NTRU extraction index missing");
            input.extract_lwe_at_to(index, &mut sample, modulus);
        }
    }

    /// Borrows matching prefixes of the intermediate and switched LWE tiles.
    /// Public boundaries already checked count <= capacity and key dimensions.
    fn lwe_tiles_mut(&mut self, count: usize) -> (&[T], &mut [T]) {
        let extracted_len = count * (self.poly_length() + 1);
        let switched_len = count * self.output_dimension.ciphertext_len();
        (
            &self.extracted[..extracted_len],
            &mut self.switched[..switched_len],
        )
    }
}
