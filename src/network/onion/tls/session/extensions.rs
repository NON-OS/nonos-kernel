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

use alloc::vec;
use alloc::vec::Vec;

pub fn build_psk_extension(
    ticket: &[u8],
    obfuscated_age: u32,
    binder_len: usize,
) -> (Vec<u8>, usize) {
    let mut identities = Vec::new();
    identities.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    identities.extend_from_slice(ticket);
    identities.extend_from_slice(&obfuscated_age.to_be_bytes());
    let mut binders = Vec::new();
    binders.push(binder_len as u8);
    binders.extend_from_slice(&vec![0u8; binder_len]);
    let mut ext_body = Vec::new();
    ext_body.extend_from_slice(&(identities.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(&identities);
    ext_body.extend_from_slice(&(binders.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(&binders);
    let binder_offset = 2 + identities.len() + 2 + 1;
    (ext_body, binder_offset)
}

pub fn build_psk_ke_modes_extension() -> Vec<u8> {
    vec![1, 0x01]
}
