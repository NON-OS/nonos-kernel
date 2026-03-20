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
use super::types::{TLSConnection, HandshakePhase};
use super::super::types::CipherSuite;
use super::super::transcript::Transcript;
use super::super::keys::KeySchedule;
use super::super::aead::AeadState;

impl TLSConnection {
    pub fn new() -> Self {
        Self {
            suite: CipherSuite::TlsAes128GcmSha256,
            transcript: Transcript::new(),
            ks: KeySchedule::new(),
            rx_hs: AeadState::empty(),
            tx_hs: AeadState::empty(),
            rx_app: None,
            tx_app: None,
            phase: HandshakePhase::Idle,
            client_random: [0u8; 32],
            ephemeral_secret: Vec::new(),
            server_random: [0u8; 32],
            server_pub: [0u8; 32],
            server_certs: Vec::new(),
            cert_verify_alg: None,
            cert_verify_sig: Vec::new(),
            cert_verify_hash: [0u8; 32],
            got_finished: false,
            recv_buffer: Vec::new(),
        }
    }
}
