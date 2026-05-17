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

use nonos_libc::mk_display_vsync_wait;

use crate::compositor_client::push_damage_commit;
use crate::paint::fill_argb;
use crate::state::Context;

// One pacer step. Returns true when a frame was actually painted so
// the runner can decide whether to skip the vsync wait (idle path).
pub fn tick(ctx: &mut Context) -> bool {
    if !ctx.fade.active() {
        return false;
    }
    let now = mk_display_vsync_wait(0);
    if now <= 0 {
        return false;
    }
    let alpha = ctx.fade.sample(now as u64);
    if alpha == ctx.alpha {
        return false;
    }
    ctx.alpha = alpha;
    let argb = ctx.current_argb();
    fill_argb(ctx.backing_va, ctx.stride, ctx.width, ctx.height, argb);
    let rid = ctx.issue_request_id();
    let _ = push_damage_commit(ctx.compositor_port, rid, 0, 0, ctx.width, ctx.height);
    true
}
