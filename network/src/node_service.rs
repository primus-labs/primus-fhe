use crate::common::OneData;
use crate::rsio::*;
use crate::rsio_grpc::*;
use crossbeam_channel::{Receiver, Sender};
use futures::prelude::*;
use log::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct MyMessageDispatcher {
    pub step_rx: Receiver<StepCallRequest>,
    pub msg_txs: Arc<Mutex<HashMap<String, Sender<OneData>>>>, // msgid --> message
}

impl MyMessageDispatcher {
    pub fn stop(&mut self) {
        info!("stop dispatcher todo!");
    }

    pub fn spawn(&mut self) {
        info!("spawn dispatcher");
        let msg_txs_lck = self.msg_txs.clone();
        let step_rx = self.step_rx.clone();
        let _dispatcher = thread::spawn(move || {
            let mut reqs: HashMap<String, VecDeque<StepCallRequest>> = HashMap::new();
            loop {
                let mut wait_t = 1_000_000; // us

                // step1, if the queue has any data
                for (__partyid, vdq) in &mut reqs {
                    loop {
                        let vdq_front = vdq.pop_front();
                        match vdq_front {
                            None => break,
                            Some(req) => {
                                let msgid = req.get_msgid();
                                let mut msg_txs = msg_txs_lck.lock().unwrap();
                                let x = msg_txs.get_mut(msgid);
                                match x {
                                    Some(tx) => {
                                        debug!(">found tx of msgid: {}", msgid);
                                        let message = req.get_content();
                                        let this_party_received_message = OneData {
                                            data: message.to_vec(),
                                        };
                                        let _ = tx.send(this_party_received_message);
                                    }
                                    None => {
                                        debug!(">not found tx of msgid: {}", msgid); // warn!
                                        vdq.push_front(req);
                                        wait_t = 1;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // step2, if the queue does not have any data
                let msg_message = step_rx.recv_timeout(Duration::from_micros(wait_t));
                match msg_message {
                    Err(err) => match err {
                        crossbeam_channel::RecvTimeoutError::Timeout => {
                            debug!("step channel recv timeout");
                        }
                        crossbeam_channel::RecvTimeoutError::Disconnected => {
                            warn!("step channel recv err {:?}", err);
                            break;
                        }
                    },
                    Ok(req) => {
                        let msgid = req.get_msgid();
                        let message = req.get_content();

                        let mut msg_txs = msg_txs_lck.lock().unwrap();
                        let x = msg_txs.get_mut(msgid);
                        match x {
                            Some(tx) => {
                                debug!("<found tx of msgid: {}", msgid);
                                let this_party_received_message = OneData {
                                    data: message.to_vec(),
                                };
                                let _ = tx.send(this_party_received_message);
                            }
                            None => {
                                debug!("<not found tx of msgid: {}", msgid); // warn!
                                if !reqs.contains_key(msgid) {
                                    reqs.insert(msgid.to_string(), VecDeque::new());
                                }
                                reqs.get_mut(msgid).unwrap().push_back(req.clone());
                            }
                        }
                        // dispatch message <<<
                    }
                }
            }
        });
        info!("spawn msg dispatcher done");
    }

    pub fn register(&mut self, msgid: String, tx: Sender<OneData>) {
        info!("register msgid: {}", msgid);
        let mut msg_txs = self.msg_txs.lock().unwrap();
        msg_txs.insert(msgid, tx);
    }
    // pub fn unregister(&mut self, msgid: String) {
    //   info!("unregister msgid:{}", msgid);
    //   let mut msg_txs = self.msg_txs.lock().unwrap();
    //   msg_txs.remove(&msgid);
    // }
}

#[derive(Clone)]
pub struct MyNodeService {
    pub step_tx: Sender<StepCallRequest>,
}

impl NodeService for MyNodeService {
    fn step_call(
        &mut self,
        ctx: grpcio::RpcContext,
        req: super::rsio::StepCallRequest,
        sink: grpcio::UnarySink<super::rsio::StepCallResponse>,
    ) {
        // directly send the message to dispather
        let _r = self.step_tx.send(req.clone());
        // let mut response = StepCallResponse::default();
        // match r {
        //   Ok(_) => {
        //   }
        //   Err(_) => {
        //   }
        // }

        let resp = StepCallResponse::default();
        debug!("recv req {:?}", req);

        let f = sink
            .success(resp)
            .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e))
            .map(|_| ());
        ctx.spawn(f)
    }
}
