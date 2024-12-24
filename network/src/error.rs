//! Error types for network I/O operations.

#[derive(Debug)]
/// Error types for network I/O operations.
pub enum NetIoError {
    /// An I/O error occurred.
    IoError(std::io::Error),
    /// Failed to acquire a mutex lock.
    MutexLockFailed(String),
    /// The requested connection was not found.
    ConnectionNotFound(u32),
    /// A timeout occurred.
    Timeout(String),
}

impl From<std::io::Error> for NetIoError {
    fn from(err: std::io::Error) -> Self {
        NetIoError::IoError(err)
    }
}

/// Type alias for network I/O results.
pub type NetIoResult<T> = std::result::Result<T, NetIoError>;
