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

use super::binding::HidBinding;
use crate::protocol::HID_BINDING_WIRE_LEN;

pub fn write_binding(out: &mut [u8], binding: HidBinding) {
    out[0] = binding.kind as u8;
    out[1] = binding.interface_number;
    out[2] = binding.endpoint_address;
    out[3] = binding.interval;
    out[4..6].copy_from_slice(&binding.max_packet_size.to_le_bytes());
    out[6..HID_BINDING_WIRE_LEN].fill(0);
}
