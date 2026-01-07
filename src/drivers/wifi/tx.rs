// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::dma::TxQueue;
use super::error::WifiError;
use alloc::vec::Vec;

pub const IEEE80211_FTYPE_MGMT: u16 = 0x0000;
pub const IEEE80211_FTYPE_CTL: u16 = 0x0004;
pub const IEEE80211_FTYPE_DATA: u16 = 0x0008;
pub const IEEE80211_STYPE_ASSOC_REQ: u16 = 0x0000;
pub const IEEE80211_STYPE_ASSOC_RESP: u16 = 0x0010;
pub const IEEE80211_STYPE_REASSOC_REQ: u16 = 0x0020;
pub const IEEE80211_STYPE_REASSOC_RESP: u16 = 0x0030;
pub const IEEE80211_STYPE_PROBE_REQ: u16 = 0x0040;
pub const IEEE80211_STYPE_PROBE_RESP: u16 = 0x0050;
pub const IEEE80211_STYPE_BEACON: u16 = 0x0080;
pub const IEEE80211_STYPE_ATIM: u16 = 0x0090;
pub const IEEE80211_STYPE_DISASSOC: u16 = 0x00A0;
pub const IEEE80211_STYPE_AUTH: u16 = 0x00B0;
pub const IEEE80211_STYPE_DEAUTH: u16 = 0x00C0;
pub const IEEE80211_STYPE_ACTION: u16 = 0x00D0;
pub const IEEE80211_STYPE_DATA: u16 = 0x0000;
pub const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;

#[repr(C, packed)]
pub struct Ieee80211Header {
    pub frame_control: u16,
    pub duration: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
}

impl Ieee80211Header {
    pub fn new_data(bssid: &[u8; 6], src: &[u8; 6], dst: &[u8; 6], seq: u16) -> Self {
        Self {
            frame_control: IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA | super::constants::IEEE80211_FC_TODS,
            duration: 0,
            addr1: *bssid,
            addr2: *src,
            addr3: *dst,
            seq_ctrl: seq << 4,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: Ieee80211Header is repr(C, packed), safe to view as bytes.
        unsafe {
            core::slice::from_raw_parts(self as *const _ as *const u8, core::mem::size_of::<Self>())
        }
    }
}

#[repr(C, packed)]
pub struct TxCmd {
    pub len: u16,
    pub next_frame_flags: u8,
    pub flags: u8,
    pub sta_id: u8,
    pub sec_ctl: u8,
    pub initial_rate_idx: u8,
    pub reserved: u8,
    pub key: [u8; 16],
    pub reserved2: [u8; 8],
    pub life_time: u32,
    pub dram_lsb_ptr: u32,
    pub dram_msb_ptr: u8,
    pub reserved3: [u8; 3],
}

impl Default for TxCmd {
    fn default() -> Self {
        Self {
            len: 0,
            next_frame_flags: 0,
            flags: 0,
            sta_id: 0,
            sec_ctl: 0,
            initial_rate_idx: 0,
            reserved: 0,
            key: [0; 16],
            reserved2: [0; 8],
            life_time: super::constants::INFINITE_LIFETIME,
            dram_lsb_ptr: 0,
            dram_msb_ptr: 0,
            reserved3: [0; 3],
        }
    }
}

pub struct TxBuilder {
    sta_id: u8,
    bssid: [u8; 6],
    src_addr: [u8; 6],
    seq_num: u16,
}

impl TxBuilder {
    pub fn new(sta_id: u8, bssid: [u8; 6], src_addr: [u8; 6]) -> Self {
        Self {
            sta_id,
            bssid,
            src_addr,
            seq_num: 0,
        }
    }

    pub fn build_data_frame(
        &mut self,
        dst: &[u8; 6],
        payload: &[u8],
    ) -> Result<Vec<u8>, WifiError> {
        let header = Ieee80211Header::new_data(&self.bssid, &self.src_addr, dst, self.seq_num);
        self.seq_num = self.seq_num.wrapping_add(1);

        let llc_snap = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];

        let mut frame = Vec::with_capacity(24 + 8 + payload.len());
        frame.extend_from_slice(header.as_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&llc_snap);
        frame.extend_from_slice(payload);

        Ok(frame)
    }

    pub fn enqueue_frame(&mut self, queue: &mut TxQueue, frame: &[u8]) -> Result<u32, WifiError> {
        queue.enqueue(frame)
    }
}

pub fn calculate_tx_time(rate_mbps: u32, length: usize) -> u32 {
    if rate_mbps == 0 {
        return 0;
    }

    let bits = (length * 8) as u32;
    let preamble_us = if rate_mbps > 11 { 20 } else { 192 };

    preamble_us + (bits * 1000) / rate_mbps
}

pub fn select_tx_rate(rssi: i8, is_5ghz: bool) -> u32 {
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
