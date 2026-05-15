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

use super::wire::call;

// compositor::OP_FOCUS_SET = 0x0004. Body: target_pid u32, _pad u32.
const OP: u16 = 0x0004;
const BODY_LEN: usize = 8;

pub fn push_focus_set(
    compositor_port: u32,
    request_id: u32,
    target_pid: u32,
) -> Result<(), &'static str> {
    let mut body = [0u8; BODY_LEN];
    body[0..4].copy_from_slice(&target_pid.to_le_bytes());
    let status = call(compositor_port, OP, request_id, &body)?;
    if status != 0 {
        return Err("compositor rejected focus_set");
    }
    Ok(())
}
