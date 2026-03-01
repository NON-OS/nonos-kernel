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

use super::constants::CBW_SIGNATURE;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CommandBlockWrapper {
    pub d_cbw_signature: u32,
    pub d_cbw_tag: u32,
    pub d_cbw_data_transfer_length: u32,
    pub bm_cbw_flags: u8,
    pub b_cbw_lun: u8,
    pub b_cbw_cb_length: u8,
    pub cbw_cb: [u8; 16],
}

impl CommandBlockWrapper {
    pub fn new(tag: u32, transfer_len: u32, flags: u8, lun: u8, cmd: &[u8]) -> Self {
        let mut cbw_cb = [0u8; 16];
        let len = cmd.len().min(16);
        cbw_cb[..len].copy_from_slice(&cmd[..len]);

        Self {
            d_cbw_signature: CBW_SIGNATURE,
            d_cbw_tag: tag,
            d_cbw_data_transfer_length: transfer_len,
            bm_cbw_flags: flags,
            b_cbw_lun: lun,
            b_cbw_cb_length: len as u8,
            cbw_cb,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Self is repr(C, packed) with fixed layout for USB BOT protocol
        unsafe {
            core::slice::from_raw_parts(
                self as *const _ as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
