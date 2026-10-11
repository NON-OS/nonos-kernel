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

//! One tick of the fetch machine.

use super::constants::TICK_MS;
use super::net_wire::NetWire;
use super::pool::Idle;
use crate::browser::net::Source;
use crate::browser::state::State;

/*
 * Every fetch in flight is stepped, the navigation first; each one that
 * ended lands in this call, its connection kept or closed; and the room that
 * frees is filled from the queues, also in this call. It used to be one
 * fetch per tick, finished on the tick after it ended, and a repaint every
 * tick whether or not anything had moved: now the window is drawn again only
 * when the status line changed or something landed on the page.
 */
/// Advance the fetches; true when something visible changed. The tick's
/// budget for proxy calls is begun once for every tab it steps
/// (`net::mixnet::new_tick`), by the caller.
pub fn tick(state: &mut State) -> bool {
    if state.sockets_port == 0 {
        return false;
    }
    let status = state.status.clone();
    let mut w = NetWire(state.sockets_port);
    let until = w.now_ms().saturating_add(TICK_MS);
    let mut shown = super::nav::step(state, &mut w, until);
    for job in state.pool.step(&mut w, until) {
        shown |= super::land::land(state, &mut w, job);
    }
    if let Some(kept) = state.keep.take() {
        let idle = Idle::kept(kept, w.now_ms());
        state.pool.park(&mut w, idle);
    }
    shown |= super::launch::launch(state, &mut w);
    shown |= styles_lapsed(state);
    shown || state.status != status
}

/// The status line once the page is shown ahead of its stylesheets.
pub const STYLES_LATE: &str = "Page shown; its styles are still arriving and apply as they come";

/* The first paint has waited as long as it does for the page's stylesheets
 * (`style_hold`): lay the page out with those that came, and run the
 * scripts that were waiting on them. */
fn styles_lapsed(state: &mut State) -> bool {
    let now = nonos_libc::mk_uptime_ms();
    if state.style_hold.restyle(now) && state.page_dom.is_some() {
        crate::browser::event::relayout(state);
        return true;
    }
    if !state.style_hold.lapse(now) {
        return false;
    }
    if state.page_dom.is_none() {
        return false;
    }
    if !super::land::run_held(state) {
        crate::browser::event::relayout(state);
    }
    state.status = alloc::string::String::from(STYLES_LATE);
    let waiting = state.css_queue.len() + state.pool.live.iter().filter(|f| f.css).count();
    let host = state.base.as_ref().map_or("", |u| u.host.as_str());
    let line = alloc::format!(
        "[BROWSER] {host}: shown before its styles, {waiting} sheets still to come after {} s\n",
        super::style_hold::STYLE_HOLD_MS / 1000
    );
    nonos_libc::mk_debug(line.as_ptr(), line.len());
    super::load_log::keep(&line);
    true
}
