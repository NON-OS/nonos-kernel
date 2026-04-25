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

use super::firewall::Firewall;
use crate::network::firewall::types::{format_ip, Action, Protocol};
use core::sync::atomic::Ordering;

impl Firewall {
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.stats.packets_allowed.load(Ordering::Relaxed),
            self.stats.packets_denied.load(Ordering::Relaxed),
            self.stats.packets_dropped.load(Ordering::Relaxed),
            self.stats.packets_logged.load(Ordering::Relaxed),
            self.stats.connections_tracked.load(Ordering::Relaxed),
        )
    }

    pub(super) fn update_action_stats(&self, action: Action) {
        match action {
            Action::Allow => self.stats.packets_allowed.fetch_add(1, Ordering::Relaxed),
            Action::Deny => self.stats.packets_denied.fetch_add(1, Ordering::Relaxed),
            Action::Drop => self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed),
            Action::RateLimit => self.stats.packets_rate_limited.fetch_add(1, Ordering::Relaxed),
            Action::Log => 0,
        };
    }

    pub(super) fn log_packet(
        &self,
        action: &Action,
        proto: Protocol,
        src_ip: [u8; 4],
        src_port: u16,
        dst_ip: [u8; 4],
        dst_port: u16,
        name: &str,
    ) {
        self.stats.packets_logged.fetch_add(1, Ordering::Relaxed);
        let act = match action {
            Action::Allow => "ALLOW",
            Action::Deny => "DENY",
            Action::Drop => "DROP",
            Action::Log => "LOG",
            Action::RateLimit => "RATELIMIT",
        };
        crate::log::info!(
            "FW: {} {:?} {}:{} -> {}:{} rule={}",
            act,
            proto,
            format_ip(src_ip),
            src_port,
            format_ip(dst_ip),
            dst_port,
            name
        );
    }
}
