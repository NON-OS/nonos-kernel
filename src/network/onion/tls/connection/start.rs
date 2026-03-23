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

use alloc::string::ToString;
use crate::network::tcp::TcpSocket;
use crate::network::onion::OnionError;
use super::types::{TLSConnection, HandshakePhase};
use super::super::types::{ContentType, TLS_1_2};
use super::super::protocol::{build_client_hello, wrap_record};
use super::super::crypto_provider::crypto;
use super::super::io::write_all;

impl TLSConnection {
    pub fn start_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        alpn: Option<&[&str]>,
    ) -> Result<(), OnionError> {
        if self.phase != HandshakePhase::Idle {
            return Err(OnionError::CryptoError);
        }
        // Cache SNI and ALPN for potential HRR ClientHello2 rebuild
        self.sni_cache = sni.map(|s| s.to_string());
        self.alpn_cache = alpn.map(|a| a.iter().map(|s| s.to_string()).collect());

        let c = crypto();
        c.random(&mut self.client_random)?;
        let (epk, esk) = c.x25519_keypair()?;
        self.ephemeral_secret = esk.to_vec();
        let ch = build_client_hello(&self.client_random, sni, alpn, &epk);
        self.transcript.add_handshake(&ch);
        write_all(sock, &wrap_record(ContentType::Handshake as u8, TLS_1_2, &ch), 10_000)?;
        self.phase = HandshakePhase::SentClientHello;
        Ok(())
    }
}
