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

use alloc::string::String;
use spin::Mutex;
use crate::network::stack::device::now_ms;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DhcpState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

#[derive(Clone)]
pub(super) struct DhcpLeaseInfo {
    pub(super) ip: [u8; 4],
    pub(super) subnet_mask: [u8; 4],
    pub(super) gateway: [u8; 4],
    pub(super) dns_primary: [u8; 4],
    pub(super) dns_secondary: [u8; 4],
    pub(super) server_ip: [u8; 4],
    pub(super) broadcast: [u8; 4],
    pub(super) domain: String,
    pub(super) lease_time: u32,
    pub(super) t1_time: u32,
    pub(super) t2_time: u32,
    pub(super) acquired_at: u64,
}

impl Default for DhcpLeaseInfo {
    fn default() -> Self {
        Self {
            ip: [0; 4],
            subnet_mask: [255, 255, 255, 0],
            gateway: [0; 4],
            dns_primary: [0; 4],
            dns_secondary: [0; 4],
            server_ip: [0; 4],
            broadcast: [0; 4],
            domain: String::new(),
            lease_time: 86400,
            t1_time: 0,
            t2_time: 0,
            acquired_at: 0,
        }
    }
}

pub(super) struct DhcpClient {
    pub(super) state: DhcpState,
    pub(super) lease: Option<DhcpLeaseInfo>,
    pub(super) xid: u32,
}

impl DhcpClient {
    pub(super) const fn new() -> Self {
        Self {
            state: DhcpState::Init,
            lease: None,
            xid: 0x4E4F4E4F,
        }
    }

    pub(super) fn new_xid(&mut self) {
        let time = crate::time::timestamp_millis();
        self.xid = (self.xid.wrapping_mul(1103515245).wrapping_add(12345)) ^ (time as u32);
    }

    pub(super) fn needs_renewal(&self) -> bool {
        if self.state != DhcpState::Bound {
            return false;
        }
        if let Some(ref lease) = self.lease {
            let elapsed = now_ms().saturating_sub(lease.acquired_at) / 1000;
            let t1 = if lease.t1_time > 0 { lease.t1_time } else { lease.lease_time / 2 };
            elapsed > t1 as u64
        } else {
            false
        }
    }

    pub(super) fn needs_rebinding(&self) -> bool {
        if self.state != DhcpState::Bound && self.state != DhcpState::Renewing {
            return false;
        }
        if let Some(ref lease) = self.lease {
            let elapsed = now_ms().saturating_sub(lease.acquired_at) / 1000;
            let t2 = if lease.t2_time > 0 { lease.t2_time } else { (lease.lease_time * 7) / 8 };
            elapsed > t2 as u64
        } else {
            false
        }
    }

    pub(super) fn lease_expired(&self) -> bool {
        if let Some(ref lease) = self.lease {
            let elapsed = now_ms().saturating_sub(lease.acquired_at) / 1000;
            elapsed > lease.lease_time as u64
        } else {
            true
        }
    }
}

pub(super) static DHCP_CLIENT: Mutex<DhcpClient> = Mutex::new(DhcpClient::new());
