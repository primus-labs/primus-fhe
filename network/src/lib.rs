//!
//! A lightweight network io library.
//!
mod rsio;
mod rsio_grpc;

pub mod common;
pub mod netio;
mod node_service;

use crate::common::NetStat;
use std::result;

#[macro_export]
macro_rules! make_default_participants {
    ($parties:expr, $partyids:expr, $base_port:expr) => {{
        Participant::from_default_partyids_baseport($parties, $partyids, $base_port)
    }};
    ($parties:expr, $base_port:expr) => {{
        Participant::from_default_baseport($parties, $base_port)
    }};
    ($parties:expr) => {{
        Participant::from_default($parties)
    }};
}

pub trait NetIO {
    /// Return self partyid.
    fn partyid(&self) -> u32;

    fn parties(&self) -> u32;

    /// Get the communication statistics.
    fn stat(&self) -> NetStat;
    fn set_send_timeout(&mut self, to: usize);

    fn set_recv_timeout(&mut self, to: usize);

    /// Recv a message from `partyid` with `msgid`.
    fn recv(&mut self, partyid: u32, msgid: &String) -> result::Result<Vec<u8>, anyhow::Error>;

    /// Send a message `data` to `partyid` with `msgid`.
    fn send(
        &mut self,
        partyid: u32,
        msgid: &String,
        data: &Vec<u8>,
    ) -> result::Result<usize, anyhow::Error>;
    /// Broadcast a message `data` to other parties(peers) with `msgid`.
    fn broadcast(&mut self, msgid: &String, data: &Vec<u8>)
        -> result::Result<usize, anyhow::Error>;
}
