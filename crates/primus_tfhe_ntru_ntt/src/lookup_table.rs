//! Ordinary PBS and ManyLUT compilers from the context's message choices.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;

use crate::{LookupTableCompiler, LookupTableError, PbsMessageConfig, TfheContext};

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares a Rounded compiler for the configured PBS/ManyLUT message domains.
    ///
    /// Copies small encoding state without allocating or borrowing this context.
    /// Input and returned messages use external q; LUT coefficients use accumulator
    /// Q. The output decoder is provided by [`Self::pbs_decryptor`]. Program
    /// capacity and output ranges are checked by the compiler methods.
    pub fn pbs_lookup_table_compiler(
        &self,
    ) -> Result<LookupTableCompiler<T, LM, BarrettModulus<T>>, LookupTableError> {
        self.pbs_lookup_table_compiler_with_messages(self.parameters().messages())
    }

    /// Prepares a compiler with independent input/output plaintext moduli.
    ///
    /// Does not change defaults or existing clients. Pair `messages.input_modulus`
    /// with [`Self::encryptor_with_message_modulus`] (or its public-key counterpart),
    /// and `messages.output_modulus` with [`Self::pbs_decryptor_with_message_modulus`].
    /// The ciphertext moduli and external secret still follow this context.
    /// Validates Rounded codecs at q/Q without preparing unused Scaled MVB state.
    /// Explicit codecs remain available through the parameter compiler factory.
    pub fn pbs_lookup_table_compiler_with_messages(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<LookupTableCompiler<T, LM, BarrettModulus<T>>, LookupTableError> {
        let parameters = self.parameters();
        let codecs = parameters.pbs_codecs(messages)?;
        parameters.lookup_table_compiler(&codecs)
    }
}
