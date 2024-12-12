use anyhow::format_err;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::ops::{Add, Div, Sub};
use std::path::Path;
use structopt::StructOpt;

#[derive(Debug, Clone)]
pub struct OneData {
    pub data: Vec<u8>,
}

#[derive(StructOpt, Debug)]
#[structopt(rename_all = "snake_case")]
pub struct CommandLineOpt {
    #[structopt(short, long, default_value = "-1")]
    pub party_id: u32,
}

/// The communication statistics
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct NetStat {
    /// Number of calls to `io.send`.
    pub sent_count: usize,
    /// The real data size.
    pub sent_bytes: usize,
    /// Total size. Protobuf serialized data (message id, real data, etc.) size.
    pub sent_bytes_all: usize,
}

impl Div<usize> for NetStat {
    type Output = NetStat;
    fn div(self, rhs: usize) -> NetStat {
        NetStat {
            sent_count: self.sent_count / rhs,
            sent_bytes: self.sent_bytes / rhs,
            sent_bytes_all: self.sent_bytes_all / rhs,
        }
    }
}

impl Add for NetStat {
    type Output = NetStat;
    fn add(self, rhs: NetStat) -> NetStat {
        NetStat {
            sent_count: self.sent_count + rhs.sent_count,
            sent_bytes: self.sent_bytes + rhs.sent_bytes,
            sent_bytes_all: self.sent_bytes_all + rhs.sent_bytes_all,
        }
    }
}

impl Sub for NetStat {
    type Output = NetStat;
    fn sub(self, rhs: NetStat) -> NetStat {
        NetStat {
            sent_count: self.sent_count - rhs.sent_count,
            sent_bytes: self.sent_bytes - rhs.sent_bytes,
            sent_bytes_all: self.sent_bytes_all - rhs.sent_bytes_all,
        }
    }
}

/// Participant info
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Participant {
    /// The party id, from 0 to n-1.
    pub partyid: u32,
    /// The node id. Not used now.
    pub nodeid: String,
    /// Now only supports valid IPv4.
    pub addr: String,
}

impl Participant {
    pub fn from_default(parties: u32) -> Vec<Participant> {
        return Participant::from_default_baseport(parties, 13500);
    }
    pub fn from_default_baseport(parties: u32, base_port: u32) -> Vec<Participant> {
        let partyids: Vec<u32> = (0..parties).collect();
        return Participant::from_default_partyids_baseport(parties, &partyids, base_port);
    }
    pub fn from_default_partyids_baseport(
        parties: u32,
        partyids: &Vec<u32>,
        base_port: u32,
    ) -> Vec<Participant> {
        assert_eq!(parties, partyids.len() as u32);
        let mut participants = Vec::new();
        for i in partyids.clone() {
            let participant = Participant {
                partyid: i,
                nodeid: "node".to_string() + &i.to_string(),
                addr: "127.0.0.1:".to_string() + &(i + base_port).to_string(),
            };
            participants.push(participant);
        }
        return participants;
    }
    pub fn from_config(config_path: &Path) -> Result<Vec<Participant>, anyhow::Error> {
        let configstr = fs::read_to_string(config_path)
            .map_err(|e| format_err!("Couldn't open {}: {}", config_path.display(), e))?;

        let participants: Vec<Participant> = serde_json::from_str(&configstr)
            .map_err(|e| format_err!("Couldn't deserialize config: {}", e))?;

        Ok(participants)
    }
}

/// For debug or simple usage.
pub fn get_default_participants(parties: u32) -> Vec<Participant> {
    Participant::from_default(parties)
}
