//! Implementation of a network I/O abstraction for multiple participants.
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::result::Result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{RECV_BUFFER_SIZE, SEND_BUFFER_SIZE};

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

/// Performance statistics for `NetIO`
#[derive(Debug, Default)]
pub struct NetIoStats {
    send_count: AtomicUsize,
    recv_count: AtomicUsize,
    send_bytes: AtomicUsize,
    recv_bytes: AtomicUsize,
    send_round: AtomicUsize,    // tcp write count
    recv_round: AtomicUsize,    // tcp read count
    send_elaps: AtomicDuration, // seconds
    recv_elaps: AtomicDuration, // seconds
}

impl NetIoStats {
    /// Retrieves the performance statistics.
    ///
    /// Returns a snapshot of the current `NetIoStats`.
    pub fn get_stats(&self) -> NetIoStats {
        NetIoStats {
            send_count: AtomicUsize::new(self.send_count.load(Ordering::Relaxed)),
            recv_count: AtomicUsize::new(self.recv_count.load(Ordering::Relaxed)),
            send_bytes: AtomicUsize::new(self.send_bytes.load(Ordering::Relaxed)),
            recv_bytes: AtomicUsize::new(self.recv_bytes.load(Ordering::Relaxed)),
            send_round: AtomicUsize::new(self.send_round.load(Ordering::Relaxed)),
            recv_round: AtomicUsize::new(self.recv_round.load(Ordering::Relaxed)),
            send_elaps: {
                let micros = self.send_elaps.load(Ordering::Relaxed);
                AtomicDuration(AtomicUsize::new(micros.as_micros() as usize))
            },
            recv_elaps: {
                let micros = self.recv_elaps.load(Ordering::Relaxed);
                AtomicDuration(AtomicUsize::new(micros.as_micros() as usize))
            },
        }
    }

    /// Converts statistics to a formatted string or JSON.
    ///
    /// # Arguments
    /// * `format` - The desired output format. `"string"` or `"json"`.
    ///
    /// # Returns
    /// A formatted string containing the statistics.
    pub fn format(&self, format: &str) -> String {
        match format {
      "json" => format!(
        r#"{{
          "send_count": {},
          "recv_count": {},
          "send_bytes": {},
          "recv_bytes": {},
          "send_round": {},
          "recv_round": {},
          "send_elaps": {}
          "recv_elaps": {}
      }}"#,
        self.send_count.load(Ordering::Relaxed),
        self.recv_count.load(Ordering::Relaxed),
        self.send_bytes.load(Ordering::Relaxed),
        self.recv_bytes.load(Ordering::Relaxed),
        self.send_round.load(Ordering::Relaxed),
        self.recv_round.load(Ordering::Relaxed),
        self.send_elaps.load(Ordering::Relaxed).as_micros() as f64 / 1e6,
        self.recv_elaps.load(Ordering::Relaxed).as_micros() as f64 / 1e6,
      ),
      _ => format!(
          "send_count: {}, recv_count: {}, send_bytes: {}, recv_bytes: {}, send_round: {}, recv_round: {}, send_elaps: {:?}, recv_elaps: {:?}",
          self.send_count.load(Ordering::Relaxed),
          self.recv_count.load(Ordering::Relaxed),
          self.send_bytes.load(Ordering::Relaxed),
          self.recv_bytes.load(Ordering::Relaxed),
          self.send_round.load(Ordering::Relaxed),
          self.recv_round.load(Ordering::Relaxed),
          self.send_elaps.load(Ordering::Relaxed).as_micros() as f64 / 1e6,
          self.recv_elaps.load(Ordering::Relaxed).as_micros() as f64 / 1e6,
      ),
    }
    }
}

/// Helper for atomic duration
#[derive(Debug, Default)]
pub struct AtomicDuration(AtomicUsize);

impl AtomicDuration {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// Adds the specified duration to the current value.
    pub fn fetch_add(&self, duration: Duration, ordering: Ordering) {
        let micros = duration.as_micros() as usize;
        self.0.fetch_add(micros, ordering);
    }

    /// Loads the current value.
    pub fn load(&self, ordering: Ordering) -> Duration {
        let micros = self.0.load(ordering);
        Duration::from_micros(micros as u64)
    }
}

impl NetIoStats {
    /// Updates the statistics for sending operations.
    pub fn update_send(&self, bytes: usize, duration: Duration) {
        self.send_count
            .fetch_add(if bytes > 0 { 1 } else { 0 }, Ordering::Relaxed);
        self.send_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.send_elaps.fetch_add(duration, Ordering::Relaxed);
    }

    /// Updates the statistics for receiving operations.
    pub fn update_recv(&self, bytes: usize, duration: Duration) {
        self.recv_count
            .fetch_add(if bytes > 0 { 1 } else { 0 }, Ordering::Relaxed);
        self.recv_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.recv_elaps.fetch_add(duration, Ordering::Relaxed);
    }
}

/// A buffer for sending and receiving data.
pub struct Buffer {
    data: Vec<u8>,
    capacity: usize,
    offset: usize,
}

impl Buffer {
    /// Create a new buffer with the specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            capacity,
            offset: 0,
        }
    }

    /// Applies to the send buffer
    /// Append data to the buffer
    /// Returns the overflow as a `Vec<u8>` if the buffer exceeds capacity
    pub fn append(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        let remaining_capacity = self.capacity - self.data.len();
        if input.len() > remaining_capacity {
            self.data.extend_from_slice(&input[..remaining_capacity]);
            Some(input[remaining_capacity..].to_vec())
        } else {
            self.data.extend_from_slice(input);
            None
        }
    }

    /// Applies to receive buffer
    /// Consume data from the buffer into the provided output slice
    pub fn consume(&mut self, output: &mut [u8]) -> usize {
        let available = self.data.len() - self.offset;
        let to_read = output.len().min(available);
        output[..to_read].copy_from_slice(&self.data[self.offset..self.offset + to_read]);
        self.offset += to_read;
        to_read
    }

    /// Used for receiving data
    /// Fill the buffer with new data
    pub fn fill(&mut self, input: &[u8]) {
        self.data.clear();
        self.offset = 0;
        self.data.extend_from_slice(input);
    }

    /// Used for sending data
    /// Clear the buffer and return all stored data
    pub fn take_all(&mut self) -> Vec<u8> {
        let result = self.data.split_off(0);
        self.offset = 0;
        result
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Get the current size of the buffer
    pub fn size(&self) -> usize {
        self.data.len() - self.offset
    }
}

/// A buffered TCP stream with send and receive buffers.
pub struct BufferedTcpStream {
    stream: TcpStream,
    send_buffer: Buffer,
    recv_buffer: Buffer,
    recv_round: AtomicUsize,
    send_round: AtomicUsize,
}

impl BufferedTcpStream {
    /// Create a buffered TCP stream
    ///
    /// # Arguments
    /// - `stream`: The TcpStream.
    /// - `send_capacity`: The capacity of the sending buffer.
    /// - `recv_capacity`: The capacity of the receiving buffer.
    ///
    pub fn new(stream: TcpStream, send_capacity: usize, recv_capacity: usize) -> Self {
        Self {
            stream,
            send_buffer: Buffer::new(send_capacity),
            recv_buffer: Buffer::new(recv_capacity),
            recv_round: AtomicUsize::new(0),
            send_round: AtomicUsize::new(0),
        }
    }

    /// Write data to the send buffer
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        if let Some(overflow) = self.send_buffer.append(data) {
            self.flush()?; // Flush the buffer if overflow occurs
            self.stream.write_all(&overflow)?; // Write the remaining data directly
            self.send_round.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Forcefully flush the send buffer
    pub fn flush(&mut self) -> std::io::Result<bool> {
        if !self.send_buffer.is_empty() {
            let data = self.send_buffer.take_all();
            self.stream.write_all(&data)?;
            self.send_round.fetch_add(1, Ordering::Relaxed);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Read data into the provided buffer
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = self.recv_buffer.consume(buf);

        while bytes_read < buf.len() {
            let mut temp_buf = vec![0; self.recv_buffer.capacity];
            match self.stream.read(&mut temp_buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    self.recv_round.fetch_add(1, Ordering::Relaxed);
                    self.recv_buffer.fill(&temp_buf[..n]);
                    bytes_read += self.recv_buffer.consume(&mut buf[bytes_read..]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break, // non-blocking read
                Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(e) => return Err(e),
            }
        }

        Ok(bytes_read)
    }

    /// Get receive rounds.
    pub fn get_recv_round(&self) -> usize {
        self.recv_round.load(Ordering::Relaxed)
    }

    /// Get send rounds.
    pub fn get_send_round(&self) -> usize {
        self.send_round.load(Ordering::Relaxed)
    }
}

impl Drop for BufferedTcpStream {
    /// Ensure that the data in the buffer is sent when the object is destroyed
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            eprintln!("BufferedTcpStream failed to flush on drop: {}", e);
        }
    }
}

/// Represents a participant in the network.
#[derive(Debug, Clone, PartialEq)]
pub struct Participant {
    /// The unique ID of the participant.
    pub id: u32,
    /// The network address of the participant in the format `IP:PORT`.
    pub address: String,
}

impl Participant {
    /// Creates a list of participants with sequential IDs and addresses.
    ///
    /// # Arguments
    /// - `count`: The number of participants.
    /// - `base_port`: The starting port number.
    ///
    /// # Returns
    /// A vector of participants.
    pub fn from_default(count: u32, base_port: u32) -> Vec<Self> {
        (0..count)
            .map(|i| Participant {
                id: i,
                address: format!("127.0.0.1:{}", base_port + i),
            })
            .collect()
    }
}

/// A network I/O abstraction for multiple participants.
///
/// Manages connections and provides methods for sending, receiving,
/// and broadcasting messages between participants.
pub struct NetIO {
    party_id: u32,
    participants: Vec<Participant>,
    connections: Arc<Mutex<HashMap<u32, BufferedTcpStream>>>,
    stats: Arc<NetIoStats>,
}

impl NetIO {
    /// Creates a new `NetIO` instance.
    ///
    /// # Arguments
    /// - `party_id`: The ID of the current participant.
    /// - `participants`: A list of all participants in the network.
    ///
    /// # Returns
    /// A `NetIO` instance or an error if initialization fails.
    pub fn new(party_id: u32, participants: Vec<Participant>) -> Result<Self, NetIoError> {
        let stats = Arc::new(NetIoStats::default());
        let mut net_io = NetIO {
            party_id,
            participants,
            connections: Arc::new(Mutex::new(HashMap::new())),
            stats,
        };
        net_io.initialize()?;
        Ok(net_io)
    }

    /// Initializes the network connections.
    fn initialize(&mut self) -> Result<(), NetIoError> {
        let self_address = &self.participants[self.party_id as usize].address;
        let listener = TcpListener::bind(self_address)
            .map_err(|e| Error::new(ErrorKind::AddrInUse, format!("Failed to bind: {}", e)))?;
        println!("Listening on {}", self_address);

        // Connect to participants
        for i in 0..self.party_id {
            let peer_address = &self.participants[i as usize].address;
            let mut stream = self.connect_with_retry(peer_address, 30)?;
            stream.write_all(&self.party_id.to_be_bytes())?; // Sends the current participant's ID to a peer
            self.setup_connection(i, stream)?;
        }

        // Accept connections from participants
        for _ in self.party_id + 1..self.participants.len() as u32 {
            let (mut stream, addr) = listener.accept().map_err(|e| {
                Error::new(ErrorKind::ConnectionAborted, format!("Accept error: {}", e))
            })?;
            println!("Connection from {}", addr);
            let mut buffer = [0u8; 4];
            stream.read_exact(&mut buffer)?; // Receives the peer's ID
            let peer_id = u32::from_be_bytes(buffer);
            self.setup_connection(peer_id, stream)?;
        }

        Ok(())
    }

    /// Connects to a peer with retries.
    fn connect_with_retry(
        &self,
        address: &str,
        max_retries: usize,
    ) -> Result<TcpStream, NetIoError> {
        for attempt in 0..max_retries {
            match TcpStream::connect(address) {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    println!(
                        "Attempt {} failed to connect to {}: {}",
                        attempt + 1,
                        address,
                        e
                    );
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
        Err(NetIoError::Timeout(format!(
            "Failed to connect to {} after {} attempts",
            address, max_retries
        )))
    }

    /// Sets up the connection.
    fn setup_connection(&mut self, id: u32, stream: TcpStream) -> Result<(), NetIoError> {
        let mut connections = self.connections.lock().map_err(|_| {
            NetIoError::MutexLockFailed("Failed to acquire lock for connection setup".to_string())
        })?;

        let buffered_stream = BufferedTcpStream::new(stream, SEND_BUFFER_SIZE, RECV_BUFFER_SIZE);
        connections.insert(id, buffered_stream);
        Ok(())
    }

    /// Receives data from a participant.
    pub fn recv(&mut self, party_id: u32, buf: &mut [u8]) -> Result<usize, NetIoError> {
        self.flush_all()?;

        let start = Instant::now();
        let mut connections = self.connections.lock().map_err(|_| {
            NetIoError::MutexLockFailed("Failed to acquire lock for recv".to_string())
        })?;
        let stream = connections
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        let bytes_read = stream.read(buf)?;
        self.stats.update_recv(bytes_read, start.elapsed());
        Ok(bytes_read)
    }

    /// Sends data to a participant.
    pub fn send(&mut self, party_id: u32, buf: &[u8]) -> Result<(), NetIoError> {
        let start = Instant::now();
        let mut connections = self.connections.lock().map_err(|_| {
            NetIoError::MutexLockFailed("Failed to acquire lock for send".to_string())
        })?;

        let stream = connections
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        stream.write(buf)?;
        self.stats.update_send(buf.len(), start.elapsed());
        Ok(())
    }

    /// Flush the send buffer.
    pub fn flush(&mut self, party_id: u32) -> Result<(), NetIoError> {
        let start = Instant::now();
        let mut connections = self.connections.lock().map_err(|_| {
            NetIoError::MutexLockFailed("Failed to acquire lock for flush".to_string())
        })?;

        let stream = connections
            .get_mut(&party_id)
            .ok_or(NetIoError::ConnectionNotFound(party_id))?;
        let flushed = stream.flush()?;
        if flushed {
            self.stats.update_send(0, start.elapsed());
        }

        Ok(())
    }

    /// Flush all send buffers.
    pub fn flush_all(&mut self) -> Result<(), NetIoError> {
        for i in 0..self.participants.len() as u32 {
            if i != self.party_id {
                self.flush(i)?;
            }
        }
        Ok(())
    }

    /// Broadcast data to all participants.
    pub fn broadcast(&mut self, buf: &[u8]) -> Result<(), NetIoError> {
        for i in 0..self.participants.len() as u32 {
            if i != self.party_id {
                self.send(i, buf)?;
            }
        }
        Ok(())
    }

    /// Get the performance statistics.
    pub fn get_stats(&self) -> Result<NetIoStats, NetIoError> {
        let mut connections = self.connections.lock().map_err(|_| {
            NetIoError::MutexLockFailed("Failed to acquire lock for flush".to_string())
        })?;
        self.stats.send_round.store(0, Ordering::Relaxed);
        self.stats.recv_round.store(0, Ordering::Relaxed);
        for (_, stream) in connections.iter_mut() {
            let sr = stream.send_round.load(Ordering::Relaxed);
            let rr = stream.recv_round.load(Ordering::Relaxed);
            self.stats.send_round.fetch_add(sr, Ordering::Relaxed);
            self.stats.recv_round.fetch_add(rr, Ordering::Relaxed);
        }

        Ok(self.stats.get_stats())
    }
}

// cargo test -- --nocapture [test_name]
#[cfg(test)]
mod tests {
    use super::Buffer;

    #[test]
    fn test_buffer_append_no_overflow() {
        let mut buffer = Buffer::new(10);
        let overflow = buffer.append(b"hello");
        assert!(overflow.is_none());
        assert_eq!(buffer.size(), 5);
    }

    #[test]
    fn test_buffer_append_with_overflow() {
        let mut buffer = Buffer::new(5);
        let overflow = buffer.append(b"hello world");
        assert!(overflow.is_some());
        assert_eq!(buffer.size(), 5);
        assert_eq!(overflow.unwrap(), b" world");
    }

    #[test]
    fn test_buffer_consume_data() {
        let mut buffer = Buffer::new(10);
        buffer.append(b"hello");
        let mut output = vec![0; 3];
        let bytes_read = buffer.consume(&mut output);
        assert_eq!(bytes_read, 3);
        assert_eq!(&output[..bytes_read], b"hel");
        assert_eq!(buffer.size(), 2);
    }

    #[test]
    fn test_buffer_consume_all_data() {
        let mut buffer = Buffer::new(10);
        buffer.append(b"hello");
        let mut output = vec![0; 10];
        let bytes_read = buffer.consume(&mut output);
        assert_eq!(bytes_read, 5);
        assert_eq!(&output[..bytes_read], b"hello");
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_buffer_fill_and_consume() {
        let mut buffer = Buffer::new(10);
        buffer.fill(b"new data");
        assert_eq!(buffer.size(), 8);
        let mut output = vec![0; 10];
        let bytes_read = buffer.consume(&mut output);
        assert_eq!(bytes_read, 8);
        assert_eq!(&output[..bytes_read], b"new data");
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_buffer_take_all() {
        let mut buffer = Buffer::new(10);
        buffer.append(b"hello");
        let data = buffer.take_all();
        assert_eq!(data, b"hello");
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_net_io_stats_update() {
        let stats = NetIoStats::default();

        stats.update_send(100, Duration::from_millis(5));
        stats.update_recv(200, Duration::from_millis(10));

        assert_eq!(stats.send_count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 200);
        assert!(stats.send_elaps.load(Ordering::Relaxed) > Duration::from_micros(4999));
        assert!(stats.recv_elaps.load(Ordering::Relaxed) > Duration::from_micros(9999));
    }

    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;

    fn setup_simple_tcp(port: u32) -> TcpStream {
        let address = format!("{}:{}", "127.0.0.1", port.to_string());
        let listener = TcpListener::bind(&address).unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0; 1024];
                let mut read_bytes = stream.read(&mut buffer).unwrap();
                let mut n = read_bytes;
                while read_bytes > 0 {
                    read_bytes = stream.read(&mut buffer[n..]).unwrap();
                    n += read_bytes;
                }
                stream.write_all(&buffer[..n]).unwrap(); // Echo received data
                thread::sleep(Duration::from_secs(1)); // Wait for the client read data
                let _ = stream.shutdown(std::net::Shutdown::Write); // Close write
            } else {
                eprintln!("setup_simple_tcp listen failed");
            }
        });

        let stream = TcpStream::connect(&address).unwrap();
        stream
    }

    #[test]
    fn test_buffered_tcp_stream_write_and_flush() {
        let stream = setup_simple_tcp(30010);
        let mut buffered_stream = BufferedTcpStream::new(stream, 10, 10);

        // Write data smaller than buffer capacity
        buffered_stream.write(b"hello").unwrap();
        assert!(!buffered_stream.send_buffer.is_empty());
        buffered_stream.flush().unwrap();
        assert!(buffered_stream.send_buffer.is_empty());
    }

    #[test]
    fn test_buffered_tcp_stream_write_with_overflow() {
        let stream = setup_simple_tcp(30020);
        let mut buffered_stream = BufferedTcpStream::new(stream, 10, 10);

        // Write data larger than buffer capacity
        buffered_stream.write(b"hello world").unwrap(); // Should flush immediately
        assert!(buffered_stream.send_buffer.is_empty());
    }

    #[test]
    fn test_buffered_tcp_stream_read() {
        let stream = setup_simple_tcp(30030);
        let mut buffered_stream = BufferedTcpStream::new(stream, 10, 10);

        // Send and read data
        buffered_stream.write(b"hello").unwrap();
        buffered_stream.flush().unwrap();
        buffered_stream.stream.shutdown(Shutdown::Write).unwrap();

        let mut response = vec![0; 5];
        let bytes_read = buffered_stream.read(&mut response).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(&response, b"hello");
    }

    #[test]
    fn test_buffered_tcp_stream_read_with_partial_buffer() {
        let stream = setup_simple_tcp(30040);
        let mut buffered_stream = BufferedTcpStream::new(stream, 10, 10);

        // Send and read data in chunks
        buffered_stream.write(b"hello world").unwrap();
        buffered_stream.flush().unwrap();
        buffered_stream.stream.shutdown(Shutdown::Write).unwrap();

        let mut response = vec![0; 5];
        let bytes_read = buffered_stream.read(&mut response).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(&response, b"hello");

        let mut response = vec![0; 6];
        let bytes_read = buffered_stream.read(&mut response).unwrap();
        assert_eq!(bytes_read, 6);
        assert_eq!(&response, b" world");
    }

    #[test]
    fn test_buffered_tcp_stream_read_with_partial_buffer2() {
        let stream = setup_simple_tcp(30050);
        let mut buffered_stream = BufferedTcpStream::new(stream, 10, 10);

        // Send and read data in chunks
        buffered_stream.write(b"hello worldhello world").unwrap();
        buffered_stream.flush().unwrap();
        buffered_stream.stream.shutdown(Shutdown::Write).unwrap();

        let mut response = vec![0; 5];
        let bytes_read = buffered_stream.read(&mut response).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(&response, b"hello");

        let mut response = vec![0; 17];
        let bytes_read = buffered_stream.read(&mut response).unwrap();
        assert_eq!(bytes_read, 17);
        assert_eq!(&response, b" worldhello world");
    }

    #[test]
    fn test_buffered_tcp_stream_flush_stats() {
        let stream = setup_simple_tcp(30060);
        let mut buffered_stream = BufferedTcpStream::new(stream, 20, 20);

        buffered_stream.write(b"Hello, World!").unwrap();
        assert_eq!(buffered_stream.get_send_round(), 0); // No write yet

        buffered_stream.flush().unwrap();
        assert_eq!(buffered_stream.get_send_round(), 1); // Write counted
    }

    #[test]
    fn test_buffered_tcp_stream_flush_stats2() {
        let stream = setup_simple_tcp(30070);
        let mut buffered_stream = BufferedTcpStream::new(stream, 10, 10);

        buffered_stream.write(b"Hello, World!").unwrap();
        assert_eq!(buffered_stream.get_send_round(), 2); // Write yet

        buffered_stream.flush().unwrap();
        assert_eq!(buffered_stream.get_send_round(), 2); // Write counted
    }

    #[test]
    fn test_net_io_send_recv() {
        let _participants = Participant::from_default(2, 40000);

        let participants = _participants.clone();
        let party1 = thread::spawn(move || {
            let mut net_io = NetIO::new(0, participants.clone()).unwrap();
            let mut buf = [0u8; 16];
            net_io.recv(1, &mut buf).unwrap();
            assert_eq!(&buf[..11], b"Hello Party");
        });

        let participants = _participants.clone();
        let party2 = thread::spawn(move || {
            let mut net_io = NetIO::new(1, participants.clone()).unwrap();
            net_io.send(0, b"Hello Party").unwrap();
        });

        party1.join().unwrap();
        party2.join().unwrap();
    }

    #[test]
    fn test_net_io_broadcast() {
        const N: u32 = 5;
        let participants = Participant::from_default(N, 40010);
        let threads: Vec<_> = (0..N)
            .map(|id| {
                let participants = participants.clone();
                thread::spawn(move || {
                    let mut net_io = NetIO::new(id, participants).unwrap();
                    if id == 0 {
                        net_io.broadcast(b"Broadcast A Message").unwrap();
                    } else {
                        let mut buf = [0u8; 19];
                        net_io.recv(0, &mut buf).unwrap();
                        assert_eq!(&buf, b"Broadcast A Message");
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_net_io_get_stats() {
        let participants = Participant::from_default(2, 40020);

        let participants_clone = participants.clone();
        thread::spawn(move || {
            let mut net_io = NetIO::new(0, participants_clone).unwrap();
            let mut buffer = vec![0u8; 1024];
            net_io.recv(1, &mut buffer).expect("Failed to receive data");
        });

        let mut net_io = NetIO::new(1, participants).unwrap();
        net_io.send(0, b"Test Message").unwrap();

        let stats = net_io.get_stats().unwrap();
        println!("Stats: {:?}", stats);
        println!("Stats (JSON): {}", stats.format("json"));
        println!("Stats (STRING): {}", stats.format(""));

        assert_eq!(stats.send_count.load(Ordering::Relaxed), 1);
        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), 12); // "Test Message" length
        assert_eq!(stats.send_round.load(Ordering::Relaxed), 0); // Have not write

        net_io.flush_all().unwrap();
        let stats = net_io.get_stats().unwrap();
        println!("Stats: {:?}", stats);
        println!("Stats (JSON): {}", stats.format("json"));
        println!("Stats (STRING): {}", stats.format(""));
        assert_eq!(stats.send_round.load(Ordering::Relaxed), 1); // Write
    }

    #[test]
    fn test_net_io_broadcast_within_sender_buffer() {
        const N: u32 = 5;
        let participants = Participant::from_default(N, 40030);
        let threads: Vec<_> = (0..N)
            .map(|id| {
                let participants = participants.clone();
                thread::spawn(move || {
                    const C: usize = N as usize - 1;
                    const MSG_SIZE: usize = SEND_BUFFER_SIZE - 1;
                    let data: Vec<u8> = (0..MSG_SIZE).map(|i| (i % 256) as u8).collect();
                    let mut net_io = NetIO::new(id, participants).unwrap();
                    if id == 0 {
                        net_io.broadcast(&data).unwrap();

                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), C);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), MSG_SIZE * C);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_round.load(Ordering::Relaxed), 0);
                        assert!(stats.send_elaps.load(Ordering::Relaxed) > Duration::ZERO);

                        net_io.flush_all().unwrap();

                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), C);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), MSG_SIZE * C);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), C);
                        assert_eq!(stats.recv_round.load(Ordering::Relaxed), 0);
                        assert!(stats.send_elaps.load(Ordering::Relaxed) > Duration::ZERO);
                    } else {
                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_round.load(Ordering::Relaxed), 0);

                        let mut buf = [0u8; MSG_SIZE];
                        net_io.recv(0, &mut buf).unwrap();
                        assert_eq!(&buf, &data[..]);

                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 1);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), MSG_SIZE);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 0);
                        assert!(stats.recv_round.load(Ordering::Relaxed) >= 1);
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn test_net_io_broadcast_over_sender_buffer() {
        const N: u32 = 5;
        let participants = Participant::from_default(N, 40040);
        let threads: Vec<_> = (0..N)
            .map(|id| {
                let participants = participants.clone();
                thread::spawn(move || {
                    const C: usize = N as usize - 1;
                    const MSG_SIZE: usize = SEND_BUFFER_SIZE + 1;
                    let data: Vec<u8> = (0..MSG_SIZE).map(|i| (i % 256) as u8).collect();
                    let mut net_io = NetIO::new(id, participants).unwrap();
                    if id == 0 {
                        net_io.broadcast(&data).unwrap();

                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), C);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), MSG_SIZE * C);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 2 * C);
                        assert_eq!(stats.recv_round.load(Ordering::Relaxed), 0);
                        assert!(stats.send_elaps.load(Ordering::Relaxed) > Duration::ZERO);

                        net_io.flush_all().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), C);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), MSG_SIZE * C);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 2 * C);
                        assert_eq!(stats.recv_round.load(Ordering::Relaxed), 0);
                        assert!(stats.send_elaps.load(Ordering::Relaxed) > Duration::ZERO);
                    } else {
                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_round.load(Ordering::Relaxed), 0);

                        let mut buf = [0u8; MSG_SIZE];
                        net_io.recv(0, &mut buf).unwrap();
                        assert_eq!(&buf, &data[..]);

                        let stats = net_io.get_stats().unwrap();
                        assert_eq!(stats.send_count.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_count.load(Ordering::Relaxed), 1);
                        assert_eq!(stats.send_bytes.load(Ordering::Relaxed), 0);
                        assert_eq!(stats.recv_bytes.load(Ordering::Relaxed), MSG_SIZE);
                        assert_eq!(stats.send_round.load(Ordering::Relaxed), 0);
                        assert!(stats.recv_round.load(Ordering::Relaxed) > 1);
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }
    }
}
