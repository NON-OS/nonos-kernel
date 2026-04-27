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
use super::super::handshake::HandshakeState;
use super::super::sae::{SaeCommit, SaeContext};
use super::types::WpaContext;
use alloc::vec::Vec;

impl WpaContext {
    pub fn init_sae(&mut self, password: &str) -> Result<SaeContext, WifiError> {
        let sae = SaeContext::new(password, &self.aa, &self.spa)?;
        Ok(sae)
    }

    pub fn process_sae_commit(
        &mut self,
        sae: &mut SaeContext,
        peer_commit: &SaeCommit,
    ) -> Result<SaeCommit, WifiError> {
        sae.set_peer_commit(peer_commit)?;

        if sae.our_commit.is_none() {
            sae.generate_commit()?;
        }

        Ok(sae.our_commit.clone().ok_or(WifiError::InvalidState)?)
    }

    pub fn process_sae_confirm(
        &mut self,
        sae: &mut SaeContext,
        peer_confirm: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        sae.verify_peer_confirm(peer_confirm)?;

        let our_confirm = sae.generate_confirm()?;

        let pmk = sae.derive_pmk()?;
        self.pmk.copy_from_slice(&pmk);

        self.state = HandshakeState::Complete;
        self.key_confirmed = true;

        Ok(our_confirm)
    }
}
