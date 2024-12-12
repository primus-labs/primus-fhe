extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use std::env;
use xio::common::*;

#[test]
fn test_log() {
    env::set_var("RUST_LOG", "trace");
    pretty_env_logger::init();

    error!("this is a error");
    warn!("this is a warning");
    info!("this is a information");
    debug!("this is a debug");
    trace!("this is a trace");
}

#[test]
fn test_participants() {
    let _ = get_default_participants(3);
}
