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

//! WiFi transmit path.


pub(super) const IEEE80211_FTYPE_DATA: u16 = 0x0008;

pub(super) const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;

#[repr(C, packed)]
pub(super) struct Ieee80211Header {
    pub frame_control: u16,
    pub duration: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
}

impl Ieee80211Header {
    pub(super) fn new_data(bssid: &[u8; 6], src: &[u8; 6], dst: &[u8; 6], seq: u16) -> Self {
        Self {
            frame_control: IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | super::constants::IEEE80211_FC_TODS,
            duration: 0,
            addr1: *bssid,
            addr2: *src,
            addr3: *dst,
            seq_ctrl: seq << 4,
        }
    }
}


pub(super) fn _calculate_tx_time(rate_mbps: u32, length: usize) -> u32 {
    if rate_mbps == 0 {
        return 0;
    }

    let bits = (length * 8) as u32;
    let preamble_us = if rate_mbps > 11 { 20 } else { 192 };

    preamble_us + (bits * 1000) / rate_mbps
}

pub(super) fn select_tx_rate(rssi: i8, is_5ghz: bool) -> u32 {
    if is_5ghz {
        if rssi >= -50 {
            866
        } else if rssi >= -60 {
            433
        } else if rssi >= -70 {
            130
        } else if rssi >= -80 {
            54
        } else {
            24
        }
    } else {
        if rssi >= -50 {
            130
        } else if rssi >= -60 {
            65
        } else if rssi >= -70 {
            54
        } else if rssi >= -80 {
            24
        } else {
            11
        }
    }
}
