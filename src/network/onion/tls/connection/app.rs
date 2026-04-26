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

use alloc::vec::Vec;
use crate::network::tcp::TcpSocket;
use crate::network::onion::OnionError;
use super::types::{TLSConnection, HandshakePhase};
use super::super::types::{ContentType, HSType, TlsSessionInfo};
use super::super::protocol::parse_handshake_view;
use super::super::session::{parse_new_session_ticket, SessionTicket, SessionCache};
use super::super::keys::Secret;
use super::super::verify::CertVerifier;

impl TLSConnection {
    /// Timeout in milliseconds for the full handshake (15 seconds).
    const HANDSHAKE_TIMEOUT_MS: u64 = 15_000;

    pub fn handshake_full(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<TlsSessionInfo, OnionError> {
        self.start_handshake(sock, sni, alpn)?;
        let deadline = crate::time::timestamp_millis() + Self::HANDSHAKE_TIMEOUT_MS;
        loop {
            if crate::time::timestamp_millis() > deadline {
                crate::sys::serial::println(b"[TLS] handshake_full: timeout");
                return Err(OnionError::Timeout);
            }
            crate::network::poll_network();
            match self.poll_handshake(sock, sni, verifier)? {
                Some(info) => return Ok(info),
                None => crate::time::yield_now(),
            }
        }
    }

    pub fn phase(&self) -> HandshakePhase { self.phase }

    pub fn encrypt_app(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let state = self.tx_app.as_mut().ok_or(OnionError::CryptoError)?;
        state.seal(self.suite, ContentType::ApplicationData, plaintext)
    }

    pub fn decrypt_app(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let state = self.rx_app.as_mut().ok_or(OnionError::CryptoError)?;
        let plaintext = state.open(self.suite, ContentType::ApplicationData, ciphertext)?;
        if plaintext.is_empty() {
            return Ok(plaintext);
        }
        // Check inner content type (last byte of decrypted TLS record)
        let inner_ct = plaintext[plaintext.len() - 1];
        if inner_ct == ContentType::Handshake as u8 {
            let data = &plaintext[..plaintext.len() - 1];
            self.process_post_handshake(data);
            // Return empty — this was a control message, not application data
            return Ok(Vec::new());
        }
        if inner_ct == ContentType::Alert as u8 {
            let data = &plaintext[..plaintext.len() - 1];
            crate::sys::serial::print(b"[TLS] encrypted alert");
            if data.len() >= 2 {
                crate::sys::serial::print(b" level=");
                crate::sys::serial::print_dec(data[0] as u64);
                crate::sys::serial::print(b" desc=");
                crate::sys::serial::print_dec(data[1] as u64);
            }
            crate::sys::serial::println(b"");
            return Err(OnionError::NetworkError);
        }
        Ok(plaintext)
    }

    /// Process post-handshake messages (NewSessionTicket).
    /// Errors are logged but not propagated — a failed ticket parse
    /// should not break the application data stream.
    fn process_post_handshake(&mut self, data: &[u8]) {
        let mut hp = data;
        while hp.len() >= 4 {
            let (typ, hbody, adv) = match parse_handshake_view(hp) {
                Ok(v) => v,
                Err(_) => break,
            };
            if typ == HSType::NewSessionTicket as u8 {
                self.handle_new_session_ticket(hbody);
            }
            hp = &hp[adv..];
        }
    }

    fn handle_new_session_ticket(&mut self, body: &[u8]) {
        let (cache, res_secret, sni): (&SessionCache, &Secret, &str) = match (
            self.session_cache,
            self.resumption_secret.as_ref(),
            self.sni_cache.as_deref(),
        ) {
            (Some(c), Some(s), Some(h)) => (c, s, h),
            _ => return,
        };

        let (lifetime, age_add, nonce, ticket_data, max_early_data) =
            match parse_new_session_ticket(body) {
                Ok(v) => v,
                Err(_) => return,
            };

        let ticket = SessionTicket {
            ticket: ticket_data,
            lifetime_secs: lifetime,
            age_add,
            nonce,
            resumption_secret: res_secret.as_slice().to_vec(),
            suite: self.suite,
            hash_len: self.suite.hash_len(),
            created_ms: crate::time::timestamp_millis(),
            max_early_data,
        };

        cache.store(sni, 443, ticket);
    }
}
