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

pub struct WpaContext {
    pub security: SecurityType,
    pub state: HandshakeState,
    pub pmk: [u8; PMK_LEN],
    pub ptk: [u8; PTK_LEN],
    pub anonce: [u8; NONCE_LEN],
    pub snonce: [u8; NONCE_LEN],
    pub aa: [u8; 6],
    pub spa: [u8; 6],
    pub replay_counter: u64,
    pub key_confirmed: bool,
}
