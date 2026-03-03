// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.


use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::network::{get_network_stack, tcp::TcpSocket};
use crate::network::onion::cell::{Cell, CELL_SIZE};
use crate::network::onion::directory::RelayDescriptor;
use crate::network::onion::tls::{TLSConnection, KERNEL_TLS_CRYPTO, STRICT_TOR_LINK_VERIFIER};
use crate::network::onion::OnionError;

use super::types::IO_WRITE_TIMEOUT_MS;

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

    pub fn handshake(&mut self) -> Result<(), OnionError> {
        crate::network::onion::tls::init_tls_stack_production(&KERNEL_TLS_CRYPTO)?;
        let alpn: [&str; 1] = ["tor"];
        let session = self.tls.handshake_full(
            &self.sock,
            None,
            Some(&alpn),
            &STRICT_TOR_LINK_VERIFIER,
        )?;
        if session.cipher_suite == 0 {
            return Err(OnionError::ConnectionFailed);
        }
        self.connected = true;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

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

    pub fn poll_read<F: FnMut(Cell)>(&mut self, mut on_cell: F) -> Result<usize, OnionError> {
        let io_timeout = super::types::IO_READ_TIMEOUT_MS;

        let mut hdr = [0u8; 5];
        match self.read_exact(&mut hdr, io_timeout) {
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
        self.read_exact(&mut body, io_timeout)?;

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
                crate::log_warn!("relay: invalid cell received, dropping 1 cell to resync");
            }
        }
        Ok(processed)
    }

    fn write_all(&self, data: &[u8], timeout_ms: u64) -> Result<(), OnionError> {
        let start = crate::time::timestamp_millis();
        if let Some(net) = get_network_stack() {
            let mut off = 0usize;
            while off < data.len() {
                if crate::time::timestamp_millis().saturating_sub(start) > timeout_ms {
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
        let start = crate::time::timestamp_millis();
        let mut filled = 0usize;

        if let Some(net) = get_network_stack() {
            while filled < dst.len() {
                if crate::time::timestamp_millis().saturating_sub(start) > timeout_ms {
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

    pub fn peer(&self) -> &RelayDescriptor {
        &self.peer
    }

    pub fn tx_count(&self) -> u64 {
        self.tx_counter.load(Ordering::Relaxed)
    }

    pub fn rx_count(&self) -> u64 {
        self.rx_counter.load(Ordering::Relaxed)
    }
}

#[inline]
pub fn wrap_tls_app_record(ciphertext: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(5 + ciphertext.len());
    rec.push(23u8);
    rec.extend_from_slice(&0x0303u16.to_be_bytes());
    rec.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    rec.extend_from_slice(ciphertext);
    rec
}
