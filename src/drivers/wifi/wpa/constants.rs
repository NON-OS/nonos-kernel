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

pub const PMK_LEN: usize = 32;
pub const PTK_LEN: usize = 64;
pub const KCK_LEN: usize = 16;
pub const KEK_LEN: usize = 16;
pub const TK_LEN: usize = 16;
pub const MIC_LEN: usize = 16;
pub const NONCE_LEN: usize = 32;
pub const REPLAY_COUNTER_LEN: usize = 8;

pub const EAPOL_KEY_TYPE_RC4: u8 = 1;
pub const EAPOL_KEY_TYPE_RSN: u8 = 2;

pub const KEY_INFO_KEY_TYPE: u16 = 0x0008;
pub const KEY_INFO_INSTALL: u16 = 0x0040;
pub const KEY_INFO_ACK: u16 = 0x0080;
pub const KEY_INFO_MIC: u16 = 0x0100;
pub const KEY_INFO_SECURE: u16 = 0x0200;
pub const KEY_INFO_ERROR: u16 = 0x0400;
pub const KEY_INFO_REQUEST: u16 = 0x0800;
pub const KEY_INFO_ENCRYPTED: u16 = 0x1000;
