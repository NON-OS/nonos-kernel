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

use alloc::collections::BTreeMap;

use super::core::DirectoryService;
use crate::network::onion::directory::types::{NetworkConsensus, SigAlg};
use crate::network::onion::directory::consensus::current_time_s;
use crate::network::onion::OnionError;
use crate::crypto::sig;

impl DirectoryService {
    /*
     * validates consensus signatures against known authority keys.
     * requires at least 3 valid ed25519 signatures for security.
     */
    pub(super) fn validate_consensus(&self, c: &mut NetworkConsensus) -> Result<(), OnionError> {
        let now = current_time_s();

        if now < c.valid_after || now > c.valid_until {
            return Err(OnionError::DirectoryError);
        }

        let auths = self.authorities.read();
        let mut id_to_ed: BTreeMap<[u8; 20], [u8; 32]> = BTreeMap::new();

        for a in auths.iter() {
            if let Some(ed) = a.ed25519_identity {
                if let Some(h) = c.authorities.iter().find(|h| h.nickname == a.nickname) {
                    id_to_ed.insert(h.identity, ed);
                }
            }
        }

        let mut good = 0usize;
        for s in &c.signatures {
            if s.signing_alg != SigAlg::Ed25519 { continue; }
            let Some(pk) = id_to_ed.get(&s.identity).copied() else { continue; };
            if sig::ed25519_verify(&pk, &c.raw_body, &s.signature).unwrap_or(false) {
                good += 1;
            }
        }

        /* tor spec requires majority of authorities, we use 3 minimum */
        if good < 3 { return Err(OnionError::DirectoryError); }
        Ok(())
    }
}
