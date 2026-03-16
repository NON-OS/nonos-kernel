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
use super::super::types::{ContentType, TlsSessionInfo};
use super::super::verify::CertVerifier;

impl TLSConnection {
    pub fn handshake_full(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<TlsSessionInfo, OnionError> {
        self.start_handshake(sock, sni, alpn)?;
        for _ in 0..100 {
            match self.poll_handshake(sock, sni, verifier)? {
                Some(info) => return Ok(info),
                None => { for _ in 0..1000 { core::hint::spin_loop(); } }
            }
        }
        Err(OnionError::Timeout)
    }

    pub fn phase(&self) -> HandshakePhase { self.phase }

    pub fn encrypt_app(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let state = self.tx_app.as_mut().ok_or(OnionError::CryptoError)?;
        state.seal(self.suite, ContentType::ApplicationData, plaintext)
    }

    pub fn decrypt_app(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, OnionError> {
        let state = self.rx_app.as_mut().ok_or(OnionError::CryptoError)?;
        state.open(self.suite, ContentType::ApplicationData, ciphertext)
    }
}
