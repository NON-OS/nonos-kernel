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

use super::constants::*;
use super::processor::_RxProcessor;
use super::types::{_FrameType, _RxFrameInfo};

impl _RxProcessor {
    pub(super) fn should_accept(&self, info: &_RxFrameInfo) -> bool {
        if info.addr1[0] & 0x01 != 0 {
            if let Some(bssid) = self.bssid_filter {
                return info.addr3 == bssid || info.addr2 == bssid;
            }
            return true;
        }
        if info.addr1 == self.our_mac {
            if let Some(bssid) = self.bssid_filter {
                return info.addr2 == bssid || info.addr3 == bssid;
            }
            return true;
        }
        if info.frame_type == _FrameType::Management {
            return self.filter_mgmt_frame(info);
        }
        false
    }

    fn filter_mgmt_frame(&self, info: &_RxFrameInfo) -> bool {
        match info.subtype {
            MGMT_SUBTYPE_BEACON | MGMT_SUBTYPE_PROBE_RESP => true,
            MGMT_SUBTYPE_AUTH | MGMT_SUBTYPE_ASSOC_RESP => {
                if let Some(bssid) = self.bssid_filter {
                    info.addr2 == bssid
                } else {
                    true
                }
            }
            MGMT_SUBTYPE_DEAUTH | MGMT_SUBTYPE_DISASSOC => {
                if let Some(bssid) = self.bssid_filter {
                    info.addr2 == bssid || info.addr3 == bssid
                } else {
                    true
                }
            }
            _ => false,
        }
    }
}
