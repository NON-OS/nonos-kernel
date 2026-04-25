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

use super::constants::{FRAME_TYPE_CTRL, FRAME_TYPE_DATA, FRAME_TYPE_MGMT};
use super::processor::_RxProcessor;
use super::types::{_FrameType, _RxFrameInfo};

impl _RxProcessor {
    pub(super) fn parse_frame(&self, data: &[u8]) -> Option<_RxFrameInfo> {
        if data.len() < 24 {
            return None;
        }
        let frame_control = u16::from_le_bytes([data[0], data[1]]);
        let frame_type_bits = ((frame_control >> 2) & 0x03) as u8;
        let subtype = ((frame_control >> 4) & 0x0F) as u8;
        let to_ds = (frame_control & 0x0100) != 0;
        let from_ds = (frame_control & 0x0200) != 0;
        let protected = (frame_control & 0x4000) != 0;
        let frame_type = match frame_type_bits {
            FRAME_TYPE_MGMT => _FrameType::Management,
            FRAME_TYPE_CTRL => _FrameType::Control,
            FRAME_TYPE_DATA => _FrameType::Data,
            _ => _FrameType::Unknown,
        };
        let mut addr1 = [0u8; 6];
        let mut addr2 = [0u8; 6];
        let mut addr3 = [0u8; 6];
        addr1.copy_from_slice(&data[4..10]);
        addr2.copy_from_slice(&data[10..16]);
        addr3.copy_from_slice(&data[16..22]);
        let seq_ctrl = u16::from_le_bytes([data[22], data[23]]);
        let seq_num = seq_ctrl >> 4;
        let mut payload_offset = 24;
        if frame_type == _FrameType::Data && (subtype & 0x08) != 0 {
            payload_offset += 2;
        }
        if (frame_control & 0x8000) != 0 {
            payload_offset += 4;
        }
        if to_ds && from_ds {
            payload_offset += 6;
        }
        let payload_len = if data.len() > payload_offset { data.len() - payload_offset } else { 0 };
        Some(_RxFrameInfo {
            frame_type,
            subtype,
            to_ds,
            from_ds,
            protected,
            addr1,
            addr2,
            addr3,
            seq_num,
            payload_offset,
            payload_len,
        })
    }
}
