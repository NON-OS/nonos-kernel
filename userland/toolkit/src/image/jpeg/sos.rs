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

use crate::image::jpeg::sof0::{FrameHeader, MAX_COMPS};
use crate::image::types::DecodeError;

#[derive(Clone, Copy)]
pub struct ScanComp {
    pub frame_index: usize,
    pub td: u8,
    pub ta: u8,
}

#[derive(Clone, Copy)]
pub struct ScanHeader {
    pub ns: u8,
    pub comps: [ScanComp; MAX_COMPS],
    pub ss: u8,
    pub se: u8,
    pub ah: u8,
    pub al: u8,
}

pub fn parse_sos(seg: &[u8], frame: &FrameHeader) -> Result<ScanHeader, DecodeError> {
    if seg.is_empty() {
        return Err(DecodeError::Truncated);
    }
    let ns = seg[0];
    if ns == 0 || (ns as usize) > MAX_COMPS || ns != frame.num_comps {
        return Err(DecodeError::Unsupported);
    }
    let need = 1 + (ns as usize) * 2 + 3;
    if seg.len() < need {
        return Err(DecodeError::Truncated);
    }
    let mut scan = ScanHeader {
        ns,
        comps: [ScanComp { frame_index: 0, td: 0, ta: 0 }; MAX_COMPS],
        ss: 0,
        se: 0,
        ah: 0,
        al: 0,
    };
    let mut p = 1usize;
    let mut i = 0usize;
    while i < ns as usize {
        let cs = seg[p];
        let tdta = seg[p + 1];
        let td = (tdta >> 4) & 0x0F;
        let ta = tdta & 0x0F;
        if td > 3 || ta > 3 {
            return Err(DecodeError::Unsupported);
        }
        let mut found = None;
        let mut j = 0usize;
        while j < frame.num_comps as usize {
            if frame.comps[j].id == cs {
                found = Some(j);
                break;
            }
            j += 1;
        }
        let fi = match found {
            Some(f) => f,
            None => return Err(DecodeError::Unsupported),
        };
        scan.comps[i].frame_index = fi;
        scan.comps[i].td = td;
        scan.comps[i].ta = ta;
        p += 2;
        i += 1;
    }
    scan.ss = seg[p];
    scan.se = seg[p + 1];
    let ahal = seg[p + 2];
    scan.ah = (ahal >> 4) & 0x0F;
    scan.al = ahal & 0x0F;
    if scan.ss != 0 || scan.se != 63 || scan.ah != 0 || scan.al != 0 {
        return Err(DecodeError::Unsupported);
    }
    Ok(scan)
}
