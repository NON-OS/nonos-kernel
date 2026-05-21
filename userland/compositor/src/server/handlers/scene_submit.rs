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

use crate::protocol::{Request, E_INVAL, SCENE_SUBMIT_REQ_LEN};
use crate::server::respond;
use crate::state::{damage::Rect, Context, Layer};

pub fn handle(ctx: &mut Context, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != SCENE_SUBMIT_REQ_LEN {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let Some(surface_handle) = super::u64_at(body, 0) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(x) = super::u32_at(body, 8) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(y) = super::u32_at(body, 12) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(width) = super::u32_at(body, 16) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(height) = super::u32_at(body, 20) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    let Some(z) = super::u32_at(body, 24) else {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    };
    if width == 0
        || height == 0
        || x.saturating_add(width) > ctx.width
        || y.saturating_add(height) > ctx.height
    {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let layer =
        Layer { owner_pid: sender_pid, surface_handle, x, y, width, height, z, in_use: true };
    if ctx.scene.submit(layer).is_err() {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    ctx.damage.accumulate(Rect { x, y, width, height });
    let _ = respond::status(sender_pid, req, 0, tx);
}
