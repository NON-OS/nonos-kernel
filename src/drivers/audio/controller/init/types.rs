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

#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub output_streams: u8,
    pub input_streams: u8,
    pub bidi_streams: u8,
    pub addr64: bool,
    pub nsdo: u8,
}

impl Capabilities {
    pub fn from_gcap(gcap: u16) -> Self {
        Self {
            output_streams: ((gcap >> 12) & 0xF) as u8,
            input_streams: ((gcap >> 8) & 0xF) as u8,
            bidi_streams: ((gcap >> 3) & 0x1F) as u8,
            addr64: (gcap & (1 << 0)) != 0,
            nsdo: ((gcap >> 1) & 0x3) as u8,
        }
    }

    pub fn total_streams(&self) -> u8 {
        self.output_streams + self.input_streams + self.bidi_streams
    }
}

impl Default for Capabilities {
    fn default() -> Self {
        Self { output_streams: 0, input_streams: 0, bidi_streams: 0, addr64: false, nsdo: 0 }
    }
}
