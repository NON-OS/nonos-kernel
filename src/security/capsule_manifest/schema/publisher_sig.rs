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

use crate::crypto::asymmetric::alg_id::{AlgId, MAX_SIG_BYTES};

use super::constants::PUBLISHER_KEY_ID_LEN;

#[derive(Debug, Clone)]
pub struct PublisherSignature {
    pub algorithm: AlgId,
    pub key_id: [u8; PUBLISHER_KEY_ID_LEN],
    pub sig: [u8; MAX_SIG_BYTES],
    pub sig_len: u16,
}

impl PublisherSignature {
    pub fn sig_bytes(&self) -> &[u8] {
        &self.sig[..self.sig_len as usize]
    }
}
