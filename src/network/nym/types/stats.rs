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

#[derive(Clone, Debug)]
pub struct NymStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub cover_packets_sent: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_routes: usize,
    pub connected_gateways: usize,
    pub known_mixnodes: usize,
}

impl Default for NymStats {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            cover_packets_sent: 0,
            bytes_sent: 0,
            bytes_received: 0,
            active_routes: 0,
            connected_gateways: 0,
            known_mixnodes: 0,
        }
    }
}

impl NymStats {
    pub fn record_packet_sent(&mut self, bytes: usize, is_cover: bool) {
        self.packets_sent = self.packets_sent.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes as u64);
        if is_cover {
            self.cover_packets_sent = self.cover_packets_sent.saturating_add(1);
        }
    }

    pub fn record_packet_received(&mut self, bytes: usize) {
        self.packets_received = self.packets_received.saturating_add(1);
        self.bytes_received = self.bytes_received.saturating_add(bytes as u64);
    }
}
