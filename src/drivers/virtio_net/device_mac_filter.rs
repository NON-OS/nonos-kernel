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

use core::sync::atomic::Ordering;

use super::device::VirtioNetDevice;
use super::error::VirtioNetError;
use super::validation;

impl VirtioNetDevice {
    pub(super) fn check_mac_filter(&self, packet: &[u8]) -> bool {
        if packet.len() < 12 {
            return false;
        }

        let src_mac: [u8; 6] = [
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
        ];

        let allowed = self.allowed_macs.lock();
        if allowed.is_empty() {
            return true;
        }

        allowed.iter().any(|mac| mac == &src_mac)
    }

    pub fn set_mac_filter_enabled(&self, enabled: bool) {
        self.mac_filter_enabled
            .store(if enabled { 1 } else { 0 }, Ordering::Release);
        crate::log::info!(
            "virtio-net: MAC filtering {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    pub fn add_allowed_mac(&self, mac: [u8; 6]) -> Result<(), VirtioNetError> {
        validation::validate_mac_address(&mac)?;
        let mut allowed = self.allowed_macs.lock();
        if !allowed.contains(&mac) {
            allowed.push(mac);
            crate::log::info!(
                "virtio-net: Added MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} to filter",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }
        Ok(())
    }

    pub fn remove_allowed_mac(&self, mac: [u8; 6]) {
        let mut allowed = self.allowed_macs.lock();
        allowed.retain(|m| m != &mac);
    }

    pub fn clear_mac_filters(&self) {
        let mut allowed = self.allowed_macs.lock();
        allowed.clear();
    }

    pub fn get_rate_limit_stats(&self) -> (u64, u64) {
        (
            self.rx_rate_limiter.get_violations(),
            self.tx_rate_limiter.get_violations(),
        )
    }

    pub fn print_security_stats(&self) {
        self.stats.snapshot().log_report();
    }
}
