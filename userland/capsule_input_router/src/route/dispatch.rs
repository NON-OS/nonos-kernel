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

use nonos_libc::InputEvent;

use crate::state::Context;

use super::deliver::deliver_one;

// Route a single event:
//   1. If a grab is held for this kind, the holder gets the event
//      exclusively.
//   2. Otherwise every subscriber whose mask includes this kind
//      receives the event.
// Returns the number of deliveries the router enqueued for this event.
pub fn route_event(ctx: &mut Context, event: &InputEvent) -> u32 {
    if let Some(holder) = ctx.grabs.holder_for(event.kind) {
        let n = deliver_one(holder, event);
        record(ctx, n);
        return n;
    }
    let mut total = 0u32;
    for pid in ctx.subscriptions.match_kind(event.kind) {
        total += deliver_one(pid, event);
    }
    record(ctx, total);
    total
}

fn record(ctx: &mut Context, delivered: u32) {
    if delivered == 0 {
        ctx.dropped_count = ctx.dropped_count.saturating_add(1);
    } else {
        ctx.delivered_count = ctx.delivered_count.saturating_add(delivered as u64);
    }
}
