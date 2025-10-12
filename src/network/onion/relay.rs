/*!
Onion Relay Link Management 
*/

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec, collections::BTreeMap, string::String};
use core::cmp::min;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::network::{get_network_stack, tcp::TcpSocket};
use crate::time;

use super::cell::{Cell, CELL_SIZE};
use super::directory::RelayDescriptor;
use super::tls::{TLSConnection, KERNEL_TLS_CRYPTO, STRICT_TOR_LINK_VERIFIER};
use super::OnionError;

/* Defaults (ms) */
const CONNECT_TIMEOUT_MS: u64 = 15_000;
const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 30_000;
const IO_READ_TIMEOUT_MS: u64 = 5_000;
const IO_WRITE_TIMEOUT_MS: u64 = 10_000;

/// link connection (client mode)
pub struct ORConnection {
    sock: TcpSocket,
    tls: TLSConnection,
    peer: RelayDescriptor,
    rx_accum: Vec<u8>,
    tx_counter: AtomicU64,
    rx_counter: AtomicU64,
    connected: bool,
}

impl ORConnection {
    pub fn new(sock: TcpSocket, peer: RelayDescriptor) -> Self {
        Self {
            sock,
            tls: TLSConnection::new(),
            peer,
            rx_accum: Vec::with_capacity(CELL_SIZE * 2),
            tx_counter: AtomicU64::new(0),
            rx_counter: AtomicU64::new(0),
            connected: false,
        }
    }

    /// Perform full TLS handshake (client) on an already-connected TCP socket.
    pub fn handshake(&mut self) -> Result<(), OnionError> {
        super::tls::init_tls_stack_production(&KERNEL_TLS_CRYPTO)?;
        let alpn: [&str; 1] = ["tor"];
        let _session = self.tls.handshake_full(&self.sock, None, Some(&alpn), &STRICT_TOR_LINK_VERIFIER)?;
        self.connected = true;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Send one Tor cell (exact CELL_SIZE).
    pub fn send_cell(&mut self, cell: &Cell) -> Result<(), OnionError> {
        let buf = cell.serialize();
        if buf.len() != CELL_SIZE {
            return Err(OnionError::InvalidCell);
        }
        let ciphertext = self.tls.encrypt_app(&buf)?;
        let rec = wrap_tls_app_record(&ciphertext);
        self.write_all(&rec, IO_WRITE_TIMEOUT_MS)?;
        self.tx_counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Poll for inbound TLS records, decrypt, assemble full cells and return count processed.
    pub fn poll_read<F: FnMut(Cell)>(&mut self, mut on_cell: F) -> Result<usize, OnionError> {
        // header
        let mut hdr = [0u8; 5];
        match self.read_exact(&mut hdr, IO_READ_TIMEOUT_MS) {
            Ok(_) => {}
            Err(OnionError::Timeout) => return Ok(0),
            Err(e) => return Err(e),
        }
        if hdr[0] != 23 || u16::from_be_bytes([hdr[1], hdr[2]]) != 0x0303 {
            return Err(OnionError::NetworkError);
        }
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if len == 0 || len > 16_384 {
            return Err(OnionError::NetworkError);
        }

        let mut body = vec![0u8; len];
        self.read_exact(&mut body, IO_READ_TIMEOUT_MS)?;

        let mut plaintext = self.tls.decrypt_app(&body)?;
        if plaintext.is_empty() {
            return Ok(0);
        }
        let inner_type = plaintext.pop().unwrap_or(23);
        if inner_type != 23 {
            return Ok(0);
        }

        self.rx_accum.extend_from_slice(&plaintext);
        let mut processed = 0usize;
        while self.rx_accum.len() >= CELL_SIZE {
            let cell_bytes = self.rx_accum.drain(..CELL_SIZE).collect::<Vec<u8>>();
            if let Ok(cell) = Cell::deserialize(&cell_bytes) {
                on_cell(cell);
                processed += 1;
                self.rx_counter.fetch_add(1, Ordering::Relaxed);
            } else {
                crate::log::warn!("relay: invalid cell received, dropping 1 cell to resync");
            }
        }
        Ok(processed)
    }

    fn write_all(&self, data: &[u8], timeout_ms: u64) -> Result<(), OnionError> {
        let start = time::timestamp_millis();
        if let Some(net) = get_network_stack() {
            let mut off = 0usize;
            while off < data.len() {
                if time::timestamp_millis().saturating_sub(start) > timeout_ms {
                    return Err(OnionError::Timeout);
                }
                match net.tcp_send(self.sock.connection_id(), &data[off..]) {
                    Ok(n) if n > 0 => off += n,
                    Ok(_) => crate::time::yield_now(),
                    Err(_) => return Err(OnionError::NetworkError),
                }
            }
            Ok(())
        } else {
            Err(OnionError::NetworkError)
        }
    }

    fn read_exact(&self, dst: &mut [u8], timeout_ms: u64) -> Result<(), OnionError> {
        let start = time::timestamp_millis();
        let mut filled = 0usize;

        if let Some(net) = get_network_stack() {
            while filled < dst.len() {
                if time::timestamp_millis().saturating_sub(start) > timeout_ms {
                    return Err(OnionError::Timeout);
                }
                let want = dst.len() - filled;
                match net.tcp_receive(self.sock.connection_id(), want) {
                    Ok(buf) if !buf.is_empty() => {
                        let n = core::cmp::min(want, buf.len());
                        dst[filled..filled + n].copy_from_slice(&buf[..n]);
                        filled += n;
                    }
                    _ => crate::time::yield_now(),
                }
            }
            Ok(())
        } else {
            Err(OnionError::NetworkError)
        }
    }
}

#[inline]
fn wrap_tls_app_record(ciphertext: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + ciphertext.len());
    rec.push(23u8);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    rec.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    rec.extend_from_slice(ciphertext);
    rec
}

/* Relay manager */

pub type LinkId = u64;

pub struct RelayManager {
    links: Mutex<BTreeMap<LinkId, Box<ORConnection>>>,
    next_id: AtomicU64,
    stats: RelayStats,
}

#[derive(Debug, Default)]
pub struct RelayStats {
    pub links_opened: AtomicU64,
    pub links_closed: AtomicU64,
    pub cells_tx: AtomicU64,
    pub cells_rx: AtomicU64,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            links: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            stats: RelayStats::default(),
        }
    }

    fn alloc_id(&self) -> LinkId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn register_and_handshake(
        &self,
        sock: TcpSocket,
        peer: RelayDescriptor,
    ) -> Result<LinkId, OnionError> {
        let mut conn = ORConnection::new(sock, peer);
        conn.handshake()?;
        let id = self.alloc_id();
        self.links.lock().insert(id, Box::new(conn));
        self.stats.links_opened.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    pub fn send_cell(&self, link: LinkId, cell: &Cell) -> Result<(), OnionError> {
        let mut guard = self.links.lock();
        if let Some(conn) = guard.get_mut(&link) {
            conn.send_cell(cell)?;
            self.stats.cells_tx.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(OnionError::NetworkError)
        }
    }

    pub fn poll<F: FnMut(Cell)>(&self, mut on_cell: F) -> usize {
        let mut total = 0usize;
        let mut dead: Vec<LinkId> = Vec::new();

        {
            let mut guard = self.links.lock();
            for (id, conn) in guard.iter_mut() {
                match conn.poll_read(|c| on_cell(c)) {
                    Ok(n) => {
                        if n > 0 {
                            self.stats.cells_rx.fetch_add(n as u64, Ordering::Relaxed);
                            total += n;
                        }
                    }
                    Err(OnionError::Timeout) => {}
                    Err(e) => {
                        crate::log::warn!("relay: link {} closed due to error: {:?}", id, e);
                        dead.push(*id);
                    }
                }
            }
        }

        if !dead.is_empty() {
            let mut guard = self.links.lock();
            for id in dead {
                guard.remove(&id);
                self.stats.links_closed.fetch_add(1, Ordering::Relaxed);
            }
        }

        total
    }

    pub fn get_stats(&self) -> &RelayStats {
        &self.stats
    }
}
