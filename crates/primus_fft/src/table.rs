use num_complex::Complex64;
use primus_shape::PolyLength;
use zeroize::Zeroize;

use crate::TorusFftValue;

/// Negacyclic FFT wrapper for polynomials modulo `X^N + 1`.
///
/// Fourier ordering and workspace layout are properties of a specific table.
/// Fourier values produced by one table must be consumed by that same table
/// instance; independently constructed tables are not interchangeable, even
/// when they use the same backend and polynomial length.
/// Table identity is a caller contract: workspace length or capacity checks
/// cannot establish where a workspace or Fourier values originated.
///
/// # Correctness
/// Every transform workspace must originate from the exact receiving table
/// instance. Fourier inputs must also use that table's ordering and scale.
/// These identity requirements are not guaranteed to be checked at runtime.
pub trait FftTable: Send + Sync {
    /// Backend-specific reusable transform workspace bound to one table.
    type Workspace;

    /// Creates a table for the checked coefficient count `N`.
    ///
    /// Implementations support the full range established by [`PolyLength`].
    #[must_use]
    fn new(poly_length: PolyLength) -> Self
    where
        Self: Sized;
    /// Returns the coefficient polynomial length `N`.
    #[must_use]
    fn poly_length(&self) -> PolyLength;
    /// Returns the number of complex Fourier values, `N / 2`.
    #[must_use]
    fn fourier_length(&self) -> usize {
        self.poly_length().fourier_poly_len()
    }
    /// Builds the frequency permutation for the negacyclic automorphism `X -> X^degree`.
    /// Entry j is `(source, conjugate)`: `output[j]` is `input[source]`, conjugated
    /// when requested. The map contains exactly N/2 entries and is bound to this
    /// table instance's Fourier order. It applies to real coefficient polynomials
    /// at either integer or torus scale. It performs no key switching.
    ///
    /// Allocate this map during evaluation-key construction and reuse it.
    ///
    /// # Panics
    /// Panics unless degree is odd and in `1..2N`.
    #[must_use]
    fn automorphism_map(&self, degree: usize) -> Vec<(usize, bool)>;

    /// Allocates a workspace compatible with this table instance.
    #[must_use]
    fn new_workspace(&self) -> Self::Workspace;
    /// Transforms torus coefficients, scaled by `2^-BITS`, to this table's
    /// Fourier form and completely overwrites `output`.
    ///
    /// `input` must contain [`Self::poly_length`] coefficients, `output` must
    /// contain [`Self::fourier_length`] complex values, and `workspace` must have
    /// been allocated by this table instance.
    ///
    /// # Panics
    ///
    /// Panics when either slice has the wrong length. Backend workspace-capacity
    /// checks may also panic; they do not validate table identity.
    fn forward_as_torus<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        workspace: &mut Self::Workspace,
    );
    /// Transforms signed integer bit patterns without torus scaling to this
    /// table's Fourier form and completely overwrites `output`.
    ///
    /// `input` must contain [`Self::poly_length`] coefficients, `output` must
    /// contain [`Self::fourier_length`] complex values, and `workspace` must have
    /// been allocated by this table instance.
    ///
    /// # Panics
    ///
    /// Panics when either slice has the wrong length. Backend workspace-capacity
    /// checks may also panic; they do not validate table identity.
    fn forward_as_integer<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        workspace: &mut Self::Workspace,
    );
    /// Converts this table's Fourier form back to torus coefficients and
    /// completely overwrites `output`.
    ///
    /// `input` must contain [`Self::fourier_length`] complex values produced
    /// for this table instance, `output` must contain [`Self::poly_length`]
    /// coefficients, and `workspace` must have been allocated by this table.
    ///
    /// # Panics
    ///
    /// Panics when either slice has the wrong length. Backend workspace-capacity
    /// checks may also panic; they do not validate table identity.
    fn backward_as_torus<T: TorusFftValue>(
        &self,
        input: &[Complex64],
        output: &mut [T],
        workspace: &mut Self::Workspace,
    );
}

/// An immutable FFT table bound to one reusable workspace allocation.
///
/// Multiple engines may share the same table across threads without locking
/// transform calls. Fourier values remain bound to that shared table and must
/// not be passed to an engine using another table instance.
pub struct FftEngine<'a, Table: FftTable + ?Sized> {
    table: &'a Table,
    workspace: Table::Workspace,
}

impl<Table: FftTable + ?Sized> FftEngine<'_, Table>
where
    Table::Workspace: Zeroize,
{
    /// Securely erases the backend workspace after a sequence of transforms.
    ///
    /// The built-in backends preserve lengths and allocations, so the engine
    /// remains reusable. They also erase their workspace on drop. A custom
    /// backend determines its own `Zeroize` and drop behavior.
    ///
    /// Transform calls do not erase workspace automatically: callers processing
    /// secrets can use this at a lifecycle boundary without adding writes to
    /// every transform. It does not erase caller-owned inputs or outputs.
    pub fn zeroize_workspace(&mut self) {
        self.workspace.zeroize();
    }
}

impl<'a, Table: FftTable + ?Sized> FftEngine<'a, Table> {
    /// Creates an engine with a fresh backend workspace.
    #[must_use]
    #[inline]
    pub fn new(table: &'a Table) -> Self {
        Self {
            table,
            workspace: table.new_workspace(),
        }
    }

    /// Returns the shared immutable table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &'a Table {
        self.table
    }

    /// Returns the coefficient polynomial length.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.table.poly_length()
    }

    /// Returns the number of complex Fourier values.
    #[must_use]
    #[inline]
    pub fn fourier_length(&self) -> usize {
        self.table.fourier_length()
    }

    /// Transforms torus coefficients to this engine's Fourier form.
    ///
    /// Completely overwrites `output`, which must contain
    /// [`Self::fourier_length`] values; `input` must contain
    /// [`Self::poly_length`] coefficients.
    ///
    /// # Panics
    ///
    /// Panics when either slice has the wrong length.
    #[inline]
    pub fn forward_as_torus<T: TorusFftValue>(&mut self, input: &[T], output: &mut [Complex64]) {
        self.table
            .forward_as_torus(input, output, &mut self.workspace);
    }

    /// Transforms signed integer bit patterns without torus scaling.
    ///
    /// Completely overwrites `output`, which must contain
    /// [`Self::fourier_length`] values; `input` must contain
    /// [`Self::poly_length`] coefficients.
    ///
    /// # Panics
    ///
    /// Panics when either slice has the wrong length.
    #[inline]
    pub fn forward_as_integer<T: TorusFftValue>(&mut self, input: &[T], output: &mut [Complex64]) {
        self.table
            .forward_as_integer(input, output, &mut self.workspace);
    }

    /// Converts this engine's Fourier form back to torus coefficients.
    ///
    /// `input` must contain [`Self::fourier_length`] values produced for this
    /// engine's table. Completely overwrites `output`, which must contain
    /// [`Self::poly_length`] coefficients.
    ///
    /// # Panics
    ///
    /// Panics when either slice has the wrong length.
    #[inline]
    pub fn backward_as_torus<T: TorusFftValue>(&mut self, input: &[Complex64], output: &mut [T]) {
        self.table
            .backward_as_torus(input, output, &mut self.workspace);
    }
}
