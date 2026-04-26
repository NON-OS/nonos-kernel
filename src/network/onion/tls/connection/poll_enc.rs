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

use alloc::vec;
use crate::network::tcp::TcpSocket;
use crate::network::onion::OnionError;
use super::types::{TLSConnection, HandshakePhase};
use super::super::types::{ContentType, HSType, TlsSessionInfo};
use super::super::protocol::{parse_certificate_chain, parse_certificate_verify, parse_handshake_view, verify_finished_with_payload};
use super::super::io::try_read;

impl TLSConnection {
    pub(super) fn poll_encrypted(&mut self, sock: &TcpSocket) -> Result<Option<TlsSessionInfo>, OnionError> {
        let mut buf = vec![0u8; 16384];
        match try_read(sock, &mut buf) {
            Ok(n) if n > 0 => self.recv_buffer.extend_from_slice(&buf[..n]),
            Ok(_) => if self.recv_buffer.is_empty() { return Ok(None); },
            Err(e) => return Err(e),
        };
        let mut offset = 0usize;
        while self.recv_buffer.len() >= offset + 5 {
            let ct = self.recv_buffer[offset];
            let len = u16::from_be_bytes([self.recv_buffer[offset + 3], self.recv_buffer[offset + 4]]) as usize;
            if self.recv_buffer.len() < offset + 5 + len { break; }
            let body = self.recv_buffer[offset + 5..offset + 5 + len].to_vec();
            match ct {
                x if x == ContentType::ApplicationData as u8 => {
                    let plaintext = match self.rx_hs.open(self.suite, ContentType::ApplicationData, &body) {
                        Ok(p) => p,
                        Err(e) => {
                            crate::sys::serial::println(b"[TLS] ERROR: encrypted HS record AEAD decrypt failed");
                            return Err(e);
                        }
                    };
                    let (&inner_type, data) = plaintext.split_last().ok_or(OnionError::CryptoError)?;
                    if inner_type == ContentType::Handshake as u8 {
                        self.hs_reassembly.extend_from_slice(data);
                        self.process_hs()?;
                    }
                }
                x if x == ContentType::Alert as u8 => {
                    crate::sys::serial::print(b"[TLS] ERROR: server sent Alert record len=");
                    crate::sys::serial::print_dec(body.len() as u64);
                    if body.len() >= 2 {
                        crate::sys::serial::print(b" level=");
                        crate::sys::serial::print_dec(body[0] as u64);
                        crate::sys::serial::print(b" desc=");
                        crate::sys::serial::print_dec(body[1] as u64);
                    }
                    crate::sys::serial::println(b"");
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::NetworkError);
                }
                _ => {}
            }
            offset += 5 + len;
        }
        if offset > 0 { self.recv_buffer.drain(..offset); }
        if self.got_finished { self.phase = HandshakePhase::ReceivedEncrypted; }
        Ok(None)
    }

    fn process_hs(&mut self) -> Result<(), OnionError> {
        let mut consumed = 0usize;
        while self.hs_reassembly.len() >= consumed + 4 {
            let view = &self.hs_reassembly[consumed..];
            let (typ, _hbody, adv) = match parse_handshake_view(view) {
                Ok(v) => v,
                Err(_) => break,
            };
            let chunk = self.hs_reassembly[consumed..consumed + adv].to_vec();
            let hbody = &chunk[4..];
            if typ == HSType::Finished as u8 {
                if !verify_finished_with_payload(&self.ks.server_hs, self.transcript.hash(), hbody) {
                    crate::sys::serial::println(b"[TLS] ERROR: Finished HMAC verification FAILED");
                    self.phase = HandshakePhase::Failed;
                    return Err(OnionError::CryptoError);
                }
                crate::sys::serial::println(b"[TLS] Finished HMAC OK");
                self.transcript.add_raw(&chunk);
                self.got_finished = true;
            } else if typ == HSType::CertificateVerify as u8 {
                // RFC 8446 §4.4.3: signature covers transcript hash EXCLUDING CertificateVerify
                let th = self.transcript.hash();
                self.cert_verify_hash[..th.len()].copy_from_slice(th);
                self.transcript.add_raw(&chunk);
                let (a, s) = parse_certificate_verify(hbody)?;
                self.cert_verify_alg = Some(a);
                self.cert_verify_sig = s;
            } else {
                self.transcript.add_raw(&chunk);
                if typ == HSType::Certificate as u8 { self.server_certs = parse_certificate_chain(hbody)?; }
            }
            consumed += adv;
        }
        if consumed > 0 { self.hs_reassembly.drain(..consumed); }
        Ok(())
    }
}
