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

use crate::protocol::{Request, GET_WALLPAPER_RESP_LEN, HDR_LEN, STATUS_LEN};
use crate::server::respond;
use crate::state::Context;

pub fn handle(ctx: &Context, sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let off = HDR_LEN + STATUS_LEN;
    tx[off..off + 4].copy_from_slice(&ctx.argb.to_le_bytes());
    tx[off + 4..off + 8].copy_from_slice(&ctx.policy.as_u32().to_le_bytes());
    tx[off + 8..off + 12].copy_from_slice(&ctx.width.to_le_bytes());
    tx[off + 12..off + 16].copy_from_slice(&ctx.height.to_le_bytes());
    tx[off + 16..off + 20].copy_from_slice(&(ctx.alpha as u32).to_le_bytes());
    tx[off + 20..off + 24].fill(0);
    let _ = respond::payload(sender_pid, req, GET_WALLPAPER_RESP_LEN, tx);
}
