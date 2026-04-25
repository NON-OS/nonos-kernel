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
    pub fn process_msg3(
        &mut self,
        frame: &[u8],
        key_data: &[u8],
        mic: &[u8],
        replay_counter: u64,
    ) -> Result<Vec<u8>, WifiError> {
        if self.state != HandshakeState::WaitingMsg3 {
            return Err(WifiError::InvalidState);
        }

        if replay_counter <= self.replay_counter {
            return Err(WifiError::ReplayAttack);
        }
        self.replay_counter = replay_counter;

        let kck = &self.ptk[0..KCK_LEN];
        if !self.verify_mic(kck, frame, mic)? {
            return Err(WifiError::MicFailure);
        }

        let kek = &self.ptk[KCK_LEN..KCK_LEN + KEK_LEN];
        let gtk = self.decrypt_key_data(kek, key_data)?;

        if gtk.is_empty() {
            return Err(WifiError::DecryptionFailed);
        }

        let msg4 = self.build_eapol_msg4()?;

        self.state = HandshakeState::Complete;
        self.key_confirmed = true;

        Ok(msg4)
    }
}
