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

use crate::network::tcp::TcpSocket;
use crate::network::onion::OnionError;
use super::types::{TLSConnection, HandshakePhase};
use super::super::types::TlsSessionInfo;
use super::super::verify::CertVerifier;

static POLL_LOG_CTR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

impl TLSConnection {
    pub fn poll_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        match self.phase {
            HandshakePhase::Idle => Err(OnionError::CryptoError),
            HandshakePhase::Complete => Ok(Some(TlsSessionInfo {
                cipher_suite: self.suite as u16,
                client_app_traffic_secret: self.ks.client_app.as_slice().to_vec(),
                server_app_traffic_secret: self.ks.server_app.as_slice().to_vec(),
            })),
            HandshakePhase::Failed => Err(OnionError::CryptoError),
            HandshakePhase::SentClientHello => {
                let n = POLL_LOG_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if n % 2000 == 0 {
                    crate::sys::serial::print(b"[TLS] poll: SentClientHello x");
                    crate::sys::serial::print_dec((n + 1) as u64);
                    crate::sys::serial::println(b"");
                }
                self.poll_server_hello(sock)
            }
            HandshakePhase::ReceivedServerHello => {
                crate::sys::serial::println(b"[TLS] poll: ReceivedServerHello");
                self.poll_encrypted(sock)
            }
            HandshakePhase::ReceivedEncrypted => {
                crate::sys::serial::println(b"[TLS] poll: ReceivedEncrypted");
                self.finish_handshake(sock, sni, verifier)
            }
            HandshakePhase::SentFinished => {
                self.phase = HandshakePhase::Complete;
                Ok(Some(TlsSessionInfo {
                    cipher_suite: self.suite as u16,
                    client_app_traffic_secret: self.ks.client_app.as_slice().to_vec(),
                    server_app_traffic_secret: self.ks.server_app.as_slice().to_vec(),
                }))
            }
        }
    }
}
