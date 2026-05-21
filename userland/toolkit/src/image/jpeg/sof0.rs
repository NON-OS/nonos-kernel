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

use crate::image::types::DecodeError;

pub const MAX_COMPS: usize = 3;

#[derive(Clone, Copy)]
pub struct Component {
    pub id: u8,
    pub h: u8,
    pub v: u8,
    pub tq: u8,
    pub td: u8,
    pub ta: u8,
}

impl Component {
    pub const fn new() -> Self {
        Self { id: 0, h: 0, v: 0, tq: 0, td: 0, ta: 0 }
    }
}

#[derive(Clone, Copy)]
pub struct FrameHeader {
    pub precision: u8,
    pub width: u16,
    pub height: u16,
    pub num_comps: u8,
    pub comps: [Component; MAX_COMPS],
    pub h_max: u8,
    pub v_max: u8,
}

impl FrameHeader {
    pub const fn new() -> Self {
        Self {
            precision: 0,
            width: 0,
            height: 0,
            num_comps: 0,
            comps: [Component::new(); MAX_COMPS],
            h_max: 0,
            v_max: 0,
        }
    }
}

pub fn parse_sof0(seg: &[u8]) -> Result<FrameHeader, DecodeError> {
    if seg.len() < 6 {
        return Err(DecodeError::Truncated);
    }
    let precision = seg[0];
    if precision != 8 {
        return Err(DecodeError::Unsupported);
    }
    let height = u16::from_be_bytes([seg[1], seg[2]]);
    let width = u16::from_be_bytes([seg[3], seg[4]]);
    let nf = seg[5];
    if height == 0 || width == 0 {
        return Err(DecodeError::BadDimensions);
    }
    if nf != 1 && nf != 3 {
        return Err(DecodeError::Unsupported);
    }
    if seg.len() < 6 + (nf as usize) * 3 {
        return Err(DecodeError::Truncated);
    }
    let mut frame = FrameHeader::new();
    frame.precision = precision;
    frame.width = width;
    frame.height = height;
    frame.num_comps = nf;
    let mut h_max = 0u8;
    let mut v_max = 0u8;
    let mut i = 0usize;
    while i < nf as usize {
        let base = 6 + i * 3;
        let id = seg[base];
        let hv = seg[base + 1];
        let tq = seg[base + 2];
        let h = (hv >> 4) & 0x0F;
        let v = hv & 0x0F;
        if h == 0 || v == 0 || h > 4 || v > 4 {
            return Err(DecodeError::Unsupported);
        }
        if tq > 3 {
            return Err(DecodeError::Unsupported);
        }
        frame.comps[i].id = id;
        frame.comps[i].h = h;
        frame.comps[i].v = v;
        frame.comps[i].tq = tq;
        if h > h_max {
            h_max = h;
        }
        if v > v_max {
            v_max = v;
        }
        i += 1;
    }
    frame.h_max = h_max;
    frame.v_max = v_max;
    if nf == 3 {
        let h0 = frame.comps[0].h;
        let v0 = frame.comps[0].v;
        let h1 = frame.comps[1].h;
        let v1 = frame.comps[1].v;
        let h2 = frame.comps[2].h;
        let v2 = frame.comps[2].v;
        if h1 != 1 || v1 != 1 || h2 != 1 || v2 != 1 {
            return Err(DecodeError::Unsupported);
        }
        let supported = (h0 == 1 && v0 == 1)
            || (h0 == 2 && v0 == 1)
            || (h0 == 1 && v0 == 2)
            || (h0 == 2 && v0 == 2);
        if !supported {
            return Err(DecodeError::Unsupported);
        }
    } else {
        if frame.comps[0].h != 1 || frame.comps[0].v != 1 {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(frame)
}
