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

use super::constants::*;
use crate::clients::envelope::call;

pub fn open(port: u32) -> Result<u32, u16> {
    let mut out = [0u8; 4];
    call(port, MAGIC, OPEN, &[], &mut out)?;
    Ok(u32::from_le_bytes(out))
}

pub fn close(port: u32, session: u32) -> Result<(), u16> {
    call(port, MAGIC, CLOSE, &session.to_le_bytes(), &mut []).map(|_| ())
}
