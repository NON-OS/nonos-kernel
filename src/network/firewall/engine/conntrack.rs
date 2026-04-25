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

extern crate alloc;

use super::firewall::Firewall;
use crate::network::firewall::types::Protocol;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl Firewall {
    pub(super) fn conn_key(
        src_ip: [u8; 4],
        _dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        proto: Protocol,
    ) -> u64 {
        let mut key: u64 = 0;
        key |= (src_ip[0] as u64) << 56;
        key |= (src_ip[1] as u64) << 48;
        key |= (src_ip[2] as u64) << 40;
        key |= (src_ip[3] as u64) << 32;
        key |= (src_port as u64) << 16;
        key |= dst_port as u64;
        key ^= (proto as u64) << 60;
        key
    }

    pub fn cleanup_expired_connections(&self) {
        let now = crate::time::timestamp_millis();
        let mut ct = self.conntrack.lock();
        let mut expired = Vec::new();
        for (key, conn) in ct.iter() {
            if now.saturating_sub(conn.last_seen_ms) > conn.timeout_ms {
                expired.push(*key);
            }
        }
        for key in expired {
            ct.remove(&key);
            self.stats.connections_expired.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn connection_count(&self) -> usize {
        self.conntrack.lock().len()
    }
}
