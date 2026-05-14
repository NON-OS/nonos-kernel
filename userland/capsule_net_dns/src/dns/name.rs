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

//! RFC 1035 name encoding. The wire form is a sequence of
//! length-prefixed labels terminated by an empty label. Responses
//! may compress repeated suffixes with a 14-bit pointer; the
//! parser handles both shapes and tracks total wire bytes
//! consumed so the caller can walk the message in sequence.

use super::types::{LABEL_MAX, NAME_MAX, POINTER_MASK};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    Truncated,
    BadPointer,
    LoopDetected,
    TooLong,
    LabelTooLong,
}

// Write `name` (e.g. "nonos.systems") into `out` as a sequence of
// length-prefixed labels followed by an empty label. Returns the
// number of bytes written. ASCII-only names; the caller is
// responsible for IDN-to-ASCII upstream.
pub fn encode(name: &str, out: &mut [u8]) -> Result<usize, NameError> {
    let mut written = 0usize;
    if name.is_empty() || name == "." {
        if out.is_empty() {
            return Err(NameError::Truncated);
        }
        out[0] = 0;
        return Ok(1);
    }
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > LABEL_MAX {
            return Err(NameError::LabelTooLong);
        }
        if written + 1 + bytes.len() + 1 > out.len() || written + 1 + bytes.len() + 1 > NAME_MAX {
            return Err(NameError::TooLong);
        }
        out[written] = bytes.len() as u8;
        out[written + 1..written + 1 + bytes.len()].copy_from_slice(bytes);
        written += 1 + bytes.len();
    }
    out[written] = 0;
    Ok(written + 1)
}

// Skip a name in `message` starting at `start`. Returns the
// position right after the name. Used by the parser to step past
// names whose value the caller does not need.
pub fn skip(message: &[u8], start: usize) -> Result<usize, NameError> {
    let mut i = start;
    let mut steps = 0;
    loop {
        if i >= message.len() {
            return Err(NameError::Truncated);
        }
        let b = message[i];
        if b == 0 {
            return Ok(i + 1);
        }
        if b & POINTER_MASK == POINTER_MASK {
            if i + 1 >= message.len() {
                return Err(NameError::Truncated);
            }
            return Ok(i + 2);
        }
        if b as usize > LABEL_MAX {
            return Err(NameError::BadPointer);
        }
        i += 1 + b as usize;
        steps += 1;
        if steps > NAME_MAX {
            return Err(NameError::LoopDetected);
        }
    }
}
