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

use crate::geometry::{clamp_to_display, Rect};
use crate::protocol::{Request, E_INVAL, E_NOMEM, WINDOW_OPEN_REQ_LEN};
use crate::server::{notify_fanout, respond};
use crate::state::Context;
use crate::window::{kind_from_u32, Visibility, Window};

pub fn handle(ctx: &mut Context, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != WINDOW_OPEN_REQ_LEN {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let window_id = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let kind_raw = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let x = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let y = u32::from_le_bytes(body[12..16].try_into().unwrap());
    let w = u32::from_le_bytes(body[16..20].try_into().unwrap());
    let h = u32::from_le_bytes(body[20..24].try_into().unwrap());
    let Some(kind) = kind_from_u32(kind_raw) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    if window_id == 0 || w == 0 || h == 0 {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let rect = clamp_to_display(Rect { x, y, width: w, height: h }, ctx.display_width, ctx.display_height);
    let z = ctx.z.allocate();
    let window = Window {
        owner_pid: sender_pid,
        window_id,
        rect,
        kind,
        visibility: Visibility::Visible,
        z,
        in_use: true,
    };
    if ctx.windows.insert(window).is_err() {
        let _ = respond::status(sender_pid, req, E_NOMEM, tx);
        return;
    }
    notify_fanout::broadcast(ctx, crate::protocol::NOTIFY_KIND_OPENED, sender_pid, window_id, rect.x, rect.y);
    let _ = respond::status(sender_pid, req, 0, tx);
}
