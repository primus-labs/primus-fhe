/// The steps of whole bootstrapping.
///
/// First `Modulus Switch` or `Scale` is decided by following two case:
/// - `Modulus Switch`: `q > 2N`, `2N|q`
/// - `Scale`:`q < 2N`, `q|2N`
#[derive(Debug, Default, Clone, Copy)]
pub enum Steps {
    /// Modulus Switch or Scale? -> Blind Rotation -> Modulus Switch -> Key Switch.
    ///
    /// (n, q) -> (n, 2N) -> (N, Q) -> (N, q) -> (n, q)
    BrMsKs,
    /// Modulus Switch or Scale? -> Blind Rotation -> Key Switch -> Modulus Switch.
    ///
    /// (n, q) -> (n, 2N) -> (N, Q) -> (n, Q) -> (n, q)
    #[default]
    BrKsRlevMs,
    /// Modulus Switch or Scale? -> Blind Rotation -> Key Switch -> Modulus Switch.
    ///
    /// (n, q) -> (n, 2N) -> (N, Q) -> (n, Q) -> (n, q)
    BrKsLevMs,
    /// Modulus Switch or Scale? -> Blind Rotation -> Modulus Switch.
    ///
    /// ### Case: n = N
    ///
    /// (n, q) -> (n, 2N) -> (N, Q) -> (n, q)
    BrMs,
}
