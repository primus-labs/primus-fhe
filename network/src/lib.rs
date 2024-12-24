#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
//! This crate provides network communication for MPC protocols.

pub mod error;
pub mod netio;

const SEND_BUFFER_SIZE: usize = 1024 * 1024;
const RECV_BUFFER_SIZE: usize = 1024 * 1024;

/// Network IO trait
pub trait IO {
    /// Get the party id of the current party.
    fn party_id(&self) -> u32;

    /// Get the number of parties in the network.
    fn party_num(&self) -> u32;

    /// Send data to a party.
    fn send(&mut self, party_id: u32, data: &[u8]) -> Result<(), error::NetIoError>;

    /// Receive data from a party.
    fn recv(&mut self, party_id: u32, buf: &mut [u8]) -> Result<usize, error::NetIoError>;

    /// Broadcast data to all parties.
    fn broadcast(&mut self, data: &[u8]) -> Result<(), error::NetIoError>;

    /// Flush the send buffer.
    fn flush(&mut self, party_id: u32) -> Result<(), error::NetIoError>;

    /// Flush all send buffers.
    fn flush_all(&mut self) -> Result<(), error::NetIoError>;
}
