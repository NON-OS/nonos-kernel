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
use super::super::types::{ContentType, TlsSessionInfo, TLS_1_2};
use super::super::protocol::{build_finished, wrap_record};
use super::super::aead::AeadState;
use super::super::verify::CertVerifier;
use super::super::io::write_all;

impl TLSConnection {
    pub(super) fn finish_handshake(
        &mut self,
        sock: &TcpSocket,
        sni: Option<&str>,
        verifier: &'static dyn CertVerifier,
    ) -> Result<Option<TlsSessionInfo>, OnionError> {
        if self.server_certs.is_empty() { self.phase = HandshakePhase::Failed; return Err(OnionError::AuthenticationFailed); }
        if let Err(e) = verifier.verify(&self.server_certs, sni.unwrap_or("")) { return Err(e); }
        self.verify_certificate_signature()?;
        let my_finished = build_finished(&self.ks.client_hs, self.transcript.hash());
        self.ks.derive_application(self.transcript.hash())?;
        self.transcript.add_handshake(&my_finished);
        let ccs = [0x01u8];
        write_all(sock, &wrap_record(ContentType::ChangeCipherSpec as u8, TLS_1_2, &ccs), 10_000)?;
        let enc = self.tx_hs.seal(self.suite, ContentType::Handshake, &my_finished)?;
        write_all(sock, &wrap_record(ContentType::ApplicationData as u8, TLS_1_2, &enc), 10_000)?;
        self.rx_app = Some(AeadState::from_secret(&self.ks.server_app, self.suite)?);
        self.tx_app = Some(AeadState::from_secret(&self.ks.client_app, self.suite)?);
        self.phase = HandshakePhase::SentFinished;
        Ok(None)
    }
}
