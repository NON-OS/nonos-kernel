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

pub type KeySerial = i32;

pub const KEY_SPEC_THREAD_KEYRING: KeySerial = -1;
pub const KEY_SPEC_PROCESS_KEYRING: KeySerial = -2;
pub const KEY_SPEC_SESSION_KEYRING: KeySerial = -3;
pub const KEY_SPEC_USER_KEYRING: KeySerial = -4;
pub const KEY_SPEC_USER_SESSION_KEYRING: KeySerial = -5;
pub const KEY_SPEC_GROUP_KEYRING: KeySerial = -6;
pub const KEY_SPEC_REQKEY_AUTH_KEY: KeySerial = -7;

pub const KEY_POS_VIEW: u32 = 0x01000000;
pub const KEY_POS_READ: u32 = 0x02000000;
pub const KEY_POS_WRITE: u32 = 0x04000000;
pub const KEY_POS_SEARCH: u32 = 0x08000000;
pub const KEY_POS_LINK: u32 = 0x10000000;
pub const KEY_POS_SETATTR: u32 = 0x20000000;
pub const KEY_POS_ALL: u32 = 0x3f000000;

pub const KEY_USR_VIEW: u32 = 0x00010000;
pub const KEY_USR_READ: u32 = 0x00020000;
pub const KEY_USR_WRITE: u32 = 0x00040000;
pub const KEY_USR_SEARCH: u32 = 0x00080000;
pub const KEY_USR_LINK: u32 = 0x00100000;
pub const KEY_USR_SETATTR: u32 = 0x00200000;
pub const KEY_USR_ALL: u32 = 0x003f0000;

pub const KEYCTL_GET_KEYRING_ID: u32 = 0;
pub const KEYCTL_JOIN_SESSION_KEYRING: u32 = 1;
pub const KEYCTL_UPDATE: u32 = 2;
pub const KEYCTL_REVOKE: u32 = 3;
pub const KEYCTL_CHOWN: u32 = 4;
pub const KEYCTL_SETPERM: u32 = 5;
pub const KEYCTL_DESCRIBE: u32 = 6;
pub const KEYCTL_CLEAR: u32 = 7;
pub const KEYCTL_LINK: u32 = 8;
pub const KEYCTL_UNLINK: u32 = 9;
pub const KEYCTL_SEARCH: u32 = 10;
pub const KEYCTL_READ: u32 = 11;
pub const KEYCTL_INSTANTIATE: u32 = 12;
pub const KEYCTL_NEGATE: u32 = 13;
pub const KEYCTL_SET_REQKEY_KEYRING: u32 = 14;
pub const KEYCTL_SET_TIMEOUT: u32 = 15;
pub const KEYCTL_ASSUME_AUTHORITY: u32 = 16;
pub const KEYCTL_GET_SECURITY: u32 = 17;
pub const KEYCTL_SESSION_TO_PARENT: u32 = 18;
pub const KEYCTL_REJECT: u32 = 19;
pub const KEYCTL_INVALIDATE: u32 = 20;
pub const KEYCTL_GET_PERSISTENT: u32 = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    User,
    Keyring,
    Logon,
    BigKey,
    Asymmetric,
    Encrypted,
    Trusted,
}

impl KeyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "keyring" => Some(Self::Keyring),
            "logon" => Some(Self::Logon),
            "big_key" => Some(Self::BigKey),
            "asymmetric" => Some(Self::Asymmetric),
            "encrypted" => Some(Self::Encrypted),
            "trusted" => Some(Self::Trusted),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Keyring => "keyring",
            Self::Logon => "logon",
            Self::BigKey => "big_key",
            Self::Asymmetric => "asymmetric",
            Self::Encrypted => "encrypted",
            Self::Trusted => "trusted",
        }
    }
}
