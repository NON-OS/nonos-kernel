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

use super::types::ProbeResult;

pub fn encode_probe(result: &ProbeResult, out: &mut [u8]) -> usize {
    out[0..4].copy_from_slice(&(result.count as u32).to_le_bytes());
    let mut pos = 4usize;
    for binding in result.bindings.iter().take(result.count) {
        out[pos] = binding.interface;
        out[pos + 1] = binding.bulk_in;
        out[pos + 2] = binding.bulk_out;
        out[pos + 3] = 0;
        out[pos + 4..pos + 6].copy_from_slice(&binding.max_packet_in.to_le_bytes());
        out[pos + 6..pos + 8].copy_from_slice(&binding.max_packet_out.to_le_bytes());
        pos += 8;
    }
    pos
}
