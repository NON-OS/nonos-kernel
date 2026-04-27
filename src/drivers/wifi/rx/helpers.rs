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

use super::processor::_RxProcessor;
use super::types::_RxFrameInfo;

impl _RxProcessor {
    pub fn get_source_mac(info: &_RxFrameInfo) -> [u8; 6] {
        match (info.to_ds, info.from_ds) {
            (false, false) => info.addr2,
            (true, false) => info.addr2,
            (false, true) => info.addr3,
            (true, true) => info.addr2,
        }
    }

    pub fn get_dest_mac(info: &_RxFrameInfo) -> [u8; 6] {
        match (info.to_ds, info.from_ds) {
            (false, false) => info.addr1,
            (true, false) => info.addr3,
            (false, true) => info.addr1,
            (true, true) => info.addr3,
        }
    }

    pub fn get_bssid(info: &_RxFrameInfo) -> [u8; 6] {
        match (info.to_ds, info.from_ds) {
            (false, false) => info.addr3,
            (true, false) => info.addr1,
            (false, true) => info.addr2,
            (true, true) => [0; 6],
        }
    }

    pub fn is_eapol_frame(data: &[u8], info: &_RxFrameInfo) -> bool {
        if info.payload_len < 8 {
            return false;
        }
        let payload = &data[info.payload_offset..];
        if payload.len() >= 8 && payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03 {
            let ether_type = u16::from_be_bytes([payload[6], payload[7]]);
            return ether_type == 0x888E;
        }
        false
    }
}
