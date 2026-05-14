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

use crate::controller::ControllerInfo;

pub const MAX_STREAMS: usize = 64;
pub const STREAM_INPUT: u8 = 1;
pub const STREAM_OUTPUT: u8 = 2;
pub const STREAM_BIDI: u8 = 3;

#[derive(Clone, Copy)]
pub struct StreamDescriptor {
    pub kind: u8,
    pub local_index: u8,
    pub global_index: u16,
    pub mmio_offset: u32,
}

pub fn layout(info: ControllerInfo) -> ([StreamDescriptor; MAX_STREAMS], usize) {
    let mut out = [empty(); MAX_STREAMS];
    let mut n = 0usize;
    append(&mut out, &mut n, STREAM_INPUT, info.input_streams);
    append(&mut out, &mut n, STREAM_OUTPUT, info.output_streams);
    append(&mut out, &mut n, STREAM_BIDI, info.bidi_streams);
    (out, n)
}

fn append(out: &mut [StreamDescriptor; MAX_STREAMS], n: &mut usize, kind: u8, count: u8) {
    let mut i = 0u8;
    while i < count && *n < MAX_STREAMS {
        out[*n] = StreamDescriptor {
            kind,
            local_index: i,
            global_index: *n as u16,
            mmio_offset: 0x80 + (*n as u32) * 0x20,
        };
        *n += 1;
        i = i.wrapping_add(1);
    }
}

const fn empty() -> StreamDescriptor {
    StreamDescriptor { kind: 0, local_index: 0, global_index: 0, mmio_offset: 0 }
}
