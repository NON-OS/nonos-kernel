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

pub(super) const MAX_KEY_SIZE: usize = 256;
pub(super) const MAX_KEYS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Symmetric = 0,
    PrivateKey = 1,
    PublicKey = 2,
    HmacSecret = 3,
    DerivedKey = 4,
    SessionKey = 5,
    MasterKey = 6,
    SigningKey = 7,
}

#[derive(Clone, Copy)]
pub(crate) struct KeyMetadata {
    pub id: u32,
    pub key_type: KeyType,
    pub size: usize,
    pub owner_pid: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub use_count: u64,
    pub locked: bool,
}

pub(super) struct KeyEntry {
    pub metadata: KeyMetadata,
    pub data: [u8; MAX_KEY_SIZE],
    pub in_use: bool,
}

impl KeyEntry {
    pub(super) const fn empty() -> Self {
        Self {
            metadata: KeyMetadata {
                id: 0,
                key_type: KeyType::Symmetric,
                size: 0,
                owner_pid: 0,
                created_at: 0,
                expires_at: 0,
                use_count: 0,
                locked: false,
            },
            data: [0u8; MAX_KEY_SIZE],
            in_use: false,
        }
    }
}
