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
use crate::dns::{LABEL_MAX, NAME_MAX, POINTER_MASK};

pub fn skip(message: &[u8], start: usize) -> Result<usize, NameError> {
    let mut i = start;
    let mut steps = 0;
    loop {
        let b = *message.get(i).ok_or(NameError::Truncated)?;
        if b == 0 {
            return Ok(i + 1);
        }
        if b & POINTER_MASK == POINTER_MASK {
            return compressed_end(message, i);
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

fn compressed_end(message: &[u8], i: usize) -> Result<usize, NameError> {
    if i + 1 >= message.len() {
        return Err(NameError::Truncated);
    }
    Ok(i + 2)
}
