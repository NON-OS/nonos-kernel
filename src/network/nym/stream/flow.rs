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

const DEFAULT_WINDOW_SIZE: u32 = 100;
const MIN_WINDOW_SIZE: u32 = 10;
const MAX_WINDOW_SIZE: u32 = 500;

pub struct FlowControl {
    send_window: u32,
    recv_window: u32,
    packets_in_flight: u32,
}

impl FlowControl {
    pub fn new() -> Self {
        Self {
            send_window: DEFAULT_WINDOW_SIZE,
            recv_window: DEFAULT_WINDOW_SIZE,
            packets_in_flight: 0,
        }
    }

    pub fn can_send(&self) -> bool {
        self.packets_in_flight < self.send_window
    }

    pub fn on_packet_sent(&mut self) {
        self.packets_in_flight = self.packets_in_flight.saturating_add(1);
    }

    pub fn on_ack_received(&mut self) {
        self.packets_in_flight = self.packets_in_flight.saturating_sub(1);
    }

    pub fn on_packet_received(&mut self) {
        self.recv_window = self.recv_window.saturating_sub(1);
    }

    pub fn send_ack(&mut self) {
        self.recv_window = DEFAULT_WINDOW_SIZE;
    }

    pub fn increase_window(&mut self) {
        if self.send_window < MAX_WINDOW_SIZE {
            self.send_window = self.send_window.saturating_add(10);
        }
    }

    pub fn decrease_window(&mut self) {
        if self.send_window > MIN_WINDOW_SIZE {
            self.send_window = self.send_window.saturating_sub(10);
        }
    }

    pub fn send_window(&self) -> u32 {
        self.send_window
    }
    pub fn recv_window(&self) -> u32 {
        self.recv_window
    }
    pub fn in_flight(&self) -> u32 {
        self.packets_in_flight
    }
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::new()
    }
}
