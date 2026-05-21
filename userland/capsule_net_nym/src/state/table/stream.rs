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

use crate::protocol::WIRE_PACKET_MAX;

use super::types::Table;

const BUFFER_PACKETS: usize = 4;

impl Table {
    pub fn append_stream(&mut self, bytes: &[u8]) {
        if self.stream_rx.len() + bytes.len() > WIRE_PACKET_MAX * BUFFER_PACKETS {
            self.stream_rx.clear();
        }
        self.stream_rx.extend_from_slice(bytes);
    }

    pub fn take_packet(&mut self, out: &mut [u8]) -> bool {
        if self.stream_rx.len() < WIRE_PACKET_MAX || out.len() < WIRE_PACKET_MAX {
            return false;
        }
        out[..WIRE_PACKET_MAX].copy_from_slice(&self.stream_rx[..WIRE_PACKET_MAX]);
        self.stream_rx.drain(..WIRE_PACKET_MAX);
        true
    }
}
