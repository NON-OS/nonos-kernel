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

use super::super::constants::*;
use super::super::handshake::HandshakeState;
use super::types::WpaContext;

impl WpaContext {
    pub fn get_temporal_key(&self) -> Option<&[u8]> {
        if self.key_confirmed {
            Some(&self.ptk[KCK_LEN + KEK_LEN..KCK_LEN + KEK_LEN + TK_LEN])
        } else {
            None
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete && self.key_confirmed
    }
}
