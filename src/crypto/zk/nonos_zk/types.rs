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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AttestationProof {
    pub msg_hash: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
    pub pubkey: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Credential {
    pub id: [u8; 32],
    pub subject_pubkey: [u8; 32],
    pub attrs_hash: [u8; 32],
    pub timestamp: u64,
    pub signature: [u8; 64],
    pub issuer_pubkey: [u8; 32],
}
