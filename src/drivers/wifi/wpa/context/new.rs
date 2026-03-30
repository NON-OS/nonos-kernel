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

use super::super::super::scan::SecurityType;
use super::super::constants::*;
use super::super::handshake::HandshakeState;
use super::types::WpaContext;

impl WpaContext {
    pub fn new(security: SecurityType, client_mac: [u8; 6], ap_mac: [u8; 6]) -> Self {
        Self {
            security,
            state: HandshakeState::Idle,
            pmk: [0u8; PMK_LEN],
            ptk: [0u8; PTK_LEN],
            anonce: [0u8; NONCE_LEN],
            snonce: [0u8; NONCE_LEN],
            aa: ap_mac,
            spa: client_mac,
            replay_counter: 0,
            key_confirmed: false,
        }
    }
}
