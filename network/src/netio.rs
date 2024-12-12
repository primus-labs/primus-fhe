//!
use crate::common::*;
use crate::node_service::*;
use crate::rsio::*;
use crate::rsio_grpc::*;
use crate::NetIO;
use ::protobuf::Message;
use anyhow::format_err;
use crossbeam_channel::*;
use grpcio::*;
use log::*;
use std::collections::{HashMap, HashSet};
use std::result;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct NetIOX {
    /// self party id
    partyid: u32,
    parties: u32,
    server: Server,
    /// {nodeid: client}
    clients: HashMap<String, NodeServiceClient>,

    /// {nodeid: partyid}, including self
    // nodeid_partyid: HashMap<String, u32>,
    /// {partyid: nodeid}, including self
    partyid_nodeid: HashMap<u32, String>,

    /// message dispatcher, (step_tx, step_rx)
    msg_dispatcher: Arc<Mutex<MyMessageDispatcher>>,

    /// {msgid: message}, recv message from MyMessageDispatcher: msg_txs.get(msgid)
    /// maybe use Arc<Mutex<HashMap<String, Receiver<OneData>>>> ?
    msg_rxs: HashMap<String, Receiver<OneData>>,
    /// msgid locker
    msgid_lock: Arc<Mutex<HashSet<String>>>,
    /// cached msgid for quickly check
    cachedid: HashSet<String>,

    /// the communication statistics
    stat: Arc<Mutex<NetStat>>,

    /// send timeout, default is 60s
    send_timeout: usize,
    /// recv timeout, default is 300s
    recv_timeout: usize,

    peerids: Vec<u32>,
}

impl NetIOX {
    //!
    //! Simple example:
    //!
    //! ```rust
    //! use xio::{common::*, netio::*, *};
    //!
    //! let partyid = 0;
    //! let participants = get_default_participants(1);
    //!
    //! let mut io = NetIOX::new(partyid, &participants).expect("new NetIO");
    //! io.stop();
    //! ```
    //!
    //! For more details see [ex01.rs](../../src/ex01/ex01.rs.html),
    //! [ex02.rs](../../src/ex02/ex02.rs.html).
    //!

    /// New a NetIO with self `partyid` and the `participants`.
    pub fn new(
        partyid: u32,
        participants: &Vec<Participant>,
    ) -> result::Result<Self, anyhow::Error> {
        // todo: valid check for partyid, addr, etc.
        let parties = participants.len() as u32;
        info!("participants: {}/{} {:?}", partyid, parties, participants);

        // init
        let mut clients = HashMap::new();
        // let mut nodeid_partyid = HashMap::new();
        let mut partyid_nodeid = HashMap::new();
        let (step_tx, step_rx) = unbounded::<StepCallRequest>();
        let mut peerids = Vec::new();

        ////////////////////////////////////////////////
        // threads
        // let threads = ThreadPoolBuilder::new()
        //   .pool_size(8)
        //   .name_prefix("task")
        //   .create()
        //   .map_err(|e| format_err!("Create threadpool Err: {}", e))
        //   .unwrap();

        ////////////////////////////////////////////////
        let msg_dispatcher = Arc::new(Mutex::new(MyMessageDispatcher {
            step_rx: step_rx.clone(),
            msg_txs: Arc::new(Mutex::new(HashMap::new())),
        }));
        {
            let mut _dispatcher = msg_dispatcher.lock().map_err(|_| error!("")).unwrap();
            _dispatcher.spawn();
        }

        ////////////////////////////////////////////////
        // server
        let env = Arc::new(Environment::new(1));
        let msg_node = MyNodeService { step_tx: step_tx };
        let msg_node_service = create_node_service(msg_node);

        let quota = ResourceQuota::new(Some("ServerQuota")).resize_memory(1024 * 1024);
        let ch_builder = ChannelBuilder::new(env.clone())
            .set_resource_quota(quota)
            .keepalive_time(Duration::from_secs(6))
            .keepalive_timeout(Duration::from_secs(21));

        let mut self_node = None;
        for p in participants {
            if partyid == p.partyid {
                self_node = Some(p.clone());
                break;
            }
        }
        if self_node == None {
            return Err(format_err!("partyid {} not exist in participants", partyid));
        }

        let self_node = self_node.unwrap();
        let vs: Vec<&str> = self_node.addr.splitn(2, ":").collect();
        let host = vs[0].to_string();
        let port = vs[1].to_string().parse::<u16>().unwrap();
        let mut server = ServerBuilder::new(env)
            .register_service(msg_node_service)
            .bind(host, port)
            .channel_args(ch_builder.build_args())
            .build()
            .map_err(|e| format_err!("Build server Err: {}", e))?;
        server.start();

        for (host, port) in server.bind_addrs() {
            info!("listening on {}:{}", host, port);
        }

        ////////////////////////////////////////////////
        // connect to clients
        for p in participants {
            // nodeid_partyid.insert(p.nodeid.clone(), p.partyid);
            partyid_nodeid.insert(p.partyid, p.nodeid.clone());
            if partyid != p.partyid {
                peerids.push(p.partyid);
                info!("{} connect to {} {}", partyid, p.partyid, p.addr);
                let env = Arc::new(EnvBuilder::new().build());
                let ch = ChannelBuilder::new(env).connect(&p.addr);
                let client = NodeServiceClient::new(ch);
                clients.insert(p.nodeid.clone(), client);
            }
        }
        peerids.sort();

        let mut s = Self {
            partyid: partyid,
            parties: parties,
            server: server,
            clients: clients,

            // nodeid_partyid: nodeid_partyid,
            partyid_nodeid: partyid_nodeid,

            msg_dispatcher: msg_dispatcher,
            msg_rxs: HashMap::new(),
            msgid_lock: Arc::new(Mutex::new(HashSet::new())),
            cachedid: HashSet::new(),

            stat: Arc::new(Mutex::new(NetStat::default())),

            send_timeout: 60,
            recv_timeout: 300,

            peerids: peerids,
        };

        {
            // for sync, init the client
            s.sync_with(&"sync-with".to_string());
            s.reset_stat();
        }

        Ok(s)
    }

    /// Sync each other
    pub fn sync_with(&mut self, msgid: &String) {
        let stat_keep = self.stat.clone();
        // for sync, init the client
        let data = "-".to_string().into_bytes();
        self.broadcast(&msgid, &data).unwrap();
        for p in self.peerids.clone() {
            let _ = self.recv(p, &msgid).unwrap();
        }
        self.stat = stat_keep;
    }

    pub fn reset_stat(&mut self) {
        let mut stat = self.stat.lock().unwrap();
        stat.sent_count = 0;
        stat.sent_bytes = 0;
        stat.sent_bytes_all = 0;
    }

    fn make_partyid_msgid(&mut self, partyid: u32, msgid: &String) -> String {
        // todo: optimized
        let msgid_ = partyid.to_string() + msgid;
        return msgid_;
    }

    fn register_channel(&mut self, msgid: &String) {
        // quickly check
        if self.cachedid.contains(msgid) {
            return;
        }

        let mut msgid_lock = self.msgid_lock.lock().unwrap();
        if msgid_lock.contains(msgid) {
            return;
        }

        // if not registered
        let (msg_tx, msg_rx) = unbounded::<OneData>();
        let mut _dispatcher = self.msg_dispatcher.lock().map_err(|_| error!("")).unwrap();
        _dispatcher.register(msgid.clone(), msg_tx);

        self.msg_rxs.insert(msgid.clone(), msg_rx);
        msgid_lock.insert(msgid.clone());
        self.cachedid.insert(msgid.clone());
    }

    // pub fn init(&mut self) {}
    pub fn stop(&mut self) {
        // todo! close & shutdown
        // close client

        // close server
        self.server.shutdown();
        {
            let mut _dispatcher = self.msg_dispatcher.lock().map_err(|_| error!("")).unwrap();
            _dispatcher.stop();
        }
    }

    pub fn agg_stat(&mut self, agg_party: u32) -> NetStat {
        let mut stat_agg = NetStat::default();
        if !self.partyid_nodeid.contains_key(&agg_party) {
            return stat_agg;
        }

        let self_stat = self.stat.lock().unwrap().clone();
        let s = bincode::serialize(&self_stat).unwrap();
        let mut stats = Vec::new();
        let msgid = "agg".to_string();

        if agg_party == self.partyid() {
            stats.push(self_stat);
            for p in self.peerids.clone() {
                let m = self.recv(p, &msgid).unwrap();
                stats.push(bincode::deserialize(&m).unwrap());
            }

            for s in stats {
                stat_agg.sent_count += s.sent_count;
                stat_agg.sent_bytes += s.sent_bytes;
                stat_agg.sent_bytes_all += s.sent_bytes_all;
            }
        } else {
            self.send(agg_party, &msgid, &s).unwrap();
        }

        stat_agg
    }

    /// Recv a message from `partyid` with `msgid`.
    pub fn recv_any(&mut self, msgid: &String) -> result::Result<Vec<u8>, anyhow::Error> {
        loop {
            let peerids = self.peerids.clone();
            for p in peerids {
                let partyid = p;
                let msgid_ = self.make_partyid_msgid(partyid, msgid);
                self.register_channel(&msgid_);

                // todo: optimized
                let rx = self.msg_rxs.get_mut(&msgid_).unwrap();

                let errmsg;
                let res = rx.recv_timeout(Duration::from_millis(1));
                match res {
                    Err(err) => match err {
                        crossbeam_channel::RecvTimeoutError::Timeout => {
                            debug!("channel recv timeout, retry");
                        }
                        crossbeam_channel::RecvTimeoutError::Disconnected => {
                            errmsg = format!("channel recv err {:?}", err);
                            return Err(format_err!("{}", errmsg));
                        }
                    },
                    Ok(vu8) => {
                        // todo: optimized
                        return Ok(vu8.data);
                    }
                }
            }
        }
    }
}

impl NetIO for NetIOX {
    /// Return self partyid.
    fn partyid(&self) -> u32 {
        return self.partyid;
    }

    fn parties(&self) -> u32 {
        return self.parties;
    }

    /// Get the communication statistics.
    fn stat(&self) -> NetStat {
        self.stat.lock().unwrap().clone()
    }

    fn set_send_timeout(&mut self, to: usize) {
        info!("set send timeout:{}", to);
        self.send_timeout = to;
    }

    fn set_recv_timeout(&mut self, to: usize) {
        info!("set recv timeout:{}", to);
        self.recv_timeout = to;
    }

    /// Recv a message from `partyid` with `msgid`.
    fn recv(&mut self, partyid: u32, msgid: &String) -> result::Result<Vec<u8>, anyhow::Error> {
        let msgid_ = self.make_partyid_msgid(partyid, msgid);
        self.register_channel(&msgid_);

        // todo: optimized
        let rx = self.msg_rxs.get_mut(&msgid_).unwrap();

        let mut loop_counter = 1;
        let errmsg;
        loop {
            loop_counter = loop_counter + 1;
            if loop_counter > self.recv_timeout {
                errmsg = format!("recv timeout loop_counter:{}", loop_counter);
                break;
            }

            let res = rx.recv_timeout(Duration::from_secs(1));
            match res {
                Err(err) => match err {
                    crossbeam_channel::RecvTimeoutError::Timeout => {
                        debug!("channel recv timeout, retry");
                    }
                    crossbeam_channel::RecvTimeoutError::Disconnected => {
                        errmsg = format!("channel recv err {:?}", err);
                        break;
                    }
                },
                Ok(vu8) => {
                    // todo: optimized
                    return Ok(vu8.data);
                }
            }
        }

        warn!("{}", errmsg);
        Err(format_err!("{}", errmsg))
    }

    /// Send a message `data` to `partyid` with `msgid`.
    ///
    fn send(
        &mut self,
        partyid: u32,
        msgid: &String,
        data: &Vec<u8>,
    ) -> result::Result<usize, anyhow::Error> {
        let msgid_ = self.make_partyid_msgid(self.partyid, msgid);
        self.register_channel(&msgid_);

        let call_opt = CallOption::default()
            .wait_for_ready(true)
            .timeout(Duration::from_secs(self.send_timeout as u64));
        // let call_opt = CallOption::default().wait_for_ready(true);
        let mut req = StepCallRequest::default();
        req.set_msgid(msgid_);
        req.set_content(data.clone());
        {
            let mut stat = self.stat.lock().unwrap();
            stat.sent_count += 1;
            stat.sent_bytes += data.len();
            stat.sent_bytes_all += req.compute_size() as usize;
        }

        let nodeid = self.partyid_nodeid.get(&partyid).unwrap();
        let client = self.clients.get_mut(nodeid).unwrap();
        let reply = client.step_call_opt(&req, call_opt);
        debug!("send reply {:?}", reply);
        match reply {
            Err(err) => Err(format_err!("send reply Err: {}", err)),
            Ok(res) => {
                if res.status == 0 {
                    Ok(data.len())
                } else {
                    Err(format_err!("send reply Err: {:?}", res))
                }
            }
        }
    }

    /// Broadcast a message `data` to other parties(peers) with `msgid`.
    fn broadcast(
        &mut self,
        msgid: &String,
        data: &Vec<u8>,
    ) -> result::Result<usize, anyhow::Error> {
        for peerid in self.peerids.clone() {
            self.send(peerid, msgid, data)?;
        }
        Ok(data.len())
    }

    // todo: nodeid version
    // fn make_nodeid_msgid(&mut self, nodeid: String, msgid: String) -> String {
    //   let msgid_ = "".to_string();
    //   return msgid_;
    // }
    // pub fn recv(&mut self, nodeid: String, msgid: String) -> Vec<u8> {
    //   return 0;
    // }
    // pub fn send(&mut self, nodeid: String, msgid: String, data: &Vec<u8>) -> usize {
    //   return 0;
    // }
}
