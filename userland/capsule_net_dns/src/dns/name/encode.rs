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

use super::error::NameError;
use crate::dns::{LABEL_MAX, NAME_MAX};

pub fn encode(name: &str, out: &mut [u8]) -> Result<usize, NameError> {
    let mut written = 0usize;
    if name.is_empty() || name == "." {
        return write_root(out);
    }
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > LABEL_MAX {
            return Err(NameError::LabelTooLong);
        }
        let next = written + 1 + bytes.len();
        if next + 1 > out.len() || next + 1 > NAME_MAX {
            return Err(NameError::TooLong);
        }
        out[written] = bytes.len() as u8;
        out[written + 1..next].copy_from_slice(bytes);
        written = next;
    }
    out[written] = 0;
    Ok(written + 1)
}

fn write_root(out: &mut [u8]) -> Result<usize, NameError> {
    if out.is_empty() {
        return Err(NameError::Truncated);
    }
    out[0] = 0;
    Ok(1)
}
