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
use super::super::types::{CipherSuite, ContentType, HSType, TlsSessionInfo};
use super::super::protocol::{has_tls12_downgrade_sentinel, parse_handshake_view, parse_server_hello};
use super::super::aead::AeadState;
use super::super::crypto_provider::crypto;
use super::super::io::try_read;

impl TLSConnection {
    pub(super) fn poll_server_hello(&mut self, sock: &TcpSocket) -> Result<Option<TlsSessionInfo>, OnionError> {
        let mut buf = vec![0u8; 16384];
        let n = match try_read(sock, &mut buf) {
            Ok(n) if n > 0 => n,
            Ok(_) => return Ok(None),
            Err(e) => return Err(e),
        };
        self.recv_buffer.extend_from_slice(&buf[..n]);
        let mut server_chosen_suite = 0u16;
        let mut cur = &self.recv_buffer[..];
        while cur.len() >= 5 {
            let ct = cur[0];
            let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;
            if cur.len() < 5 + len { break; }
            let payload = &cur[5..5 + len];
            match ct {
                x if x == ContentType::Handshake as u8 => {
                    let mut hp = payload;
                    while hp.len() >= 4 {
                        let (typ, body, adv) = parse_handshake_view(hp)?;
                        if typ == HSType::ServerHello as u8 {
                            self.transcript.add_raw(&hp[..adv]);
                            let (suite, sv_pub, sv_random) = parse_server_hello(body)?;
                            server_chosen_suite = suite;
                            self.server_pub.copy_from_slice(&sv_pub);
                            self.server_random.copy_from_slice(&sv_random);
                        }
                        hp = &hp[adv..];
                    }
                }
                x if x == ContentType::Alert as u8 => { self.phase = HandshakePhase::Failed; return Err(OnionError::NetworkError); }
                x if x == ContentType::ApplicationData as u8 => break,
                _ => {}
            }
            cur = &cur[5 + len..];
        }
        if server_chosen_suite == 0 { return Ok(None); }
        if has_tls12_downgrade_sentinel(&self.server_random) { self.phase = HandshakePhase::Failed; return Err(OnionError::CryptoError); }
        self.suite = match server_chosen_suite { 0x1301 => CipherSuite::TlsAes128GcmSha256, 0x1303 => CipherSuite::TlsChacha20Poly1305Sha256, _ => { self.phase = HandshakePhase::Failed; return Err(OnionError::CryptoError); } };
        let c = crypto();
        let mut esk = [0u8; 32];
        esk.copy_from_slice(&self.ephemeral_secret);
        let shared = c.x25519(&esk, &self.server_pub)?;
        self.ks.derive_after_sh(&shared, self.transcript.hash())?;
        self.rx_hs = AeadState::from_secret(&self.ks.server_hs, self.suite)?;
        self.tx_hs = AeadState::from_secret(&self.ks.client_hs, self.suite)?;
        let consumed = self.recv_buffer.len() - cur.len();
        self.recv_buffer.drain(..consumed);
        self.phase = HandshakePhase::ReceivedServerHello;
        Ok(None)
    }
}
