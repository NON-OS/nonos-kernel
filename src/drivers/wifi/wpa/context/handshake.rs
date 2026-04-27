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

use super::super::super::error::WifiError;
use super::super::constants::*;
use super::super::handshake::HandshakeState;
use super::types::WpaContext;
use alloc::vec::Vec;

impl WpaContext {
    pub fn process_msg1(
        &mut self,
        anonce: &[u8],
        replay_counter: u64,
    ) -> Result<Vec<u8>, WifiError> {
        if self.state != HandshakeState::Idle {
            return Err(WifiError::InvalidState);
        }

        if anonce.len() != NONCE_LEN {
            return Err(WifiError::InvalidFrame);
        }
        self.anonce.copy_from_slice(anonce);
        self.replay_counter = replay_counter;

        self.generate_snonce()?;
        self.derive_ptk()?;

        let msg2 = self.build_eapol_msg2()?;

        self.state = HandshakeState::WaitingMsg3;
        Ok(msg2)
    }
}
