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

//! The `run` frame loop for one open window: service input, tick the app when
//! its interval has passed, then block until the next message or deadline.
//! It returns when the window is closed.

use nonos_libc::mk_uptime_ms;

use crate::app::App;
use crate::discover::Peers;

use super::boot::BootedApp;
use super::pace;
use super::refresh_input::beat_left;
use super::repaint::repaint;
use super::service_frame::service_frame;
use super::theme_follow;

pub(super) fn frame_loop<A: App>(
    booted: &mut BootedApp<A>,
    rx: &mut [u8],
    peers: &Peers,
    request_id: &mut u32,
) {
    /*
     * None ticks on the first frame, as the old zero start time did.
     */
    let mut last_tick: Option<i64> = None;
    loop {
        if service_frame(booted, rx, peers, request_id) {
            return;
        }
        if theme_follow::follow() && !booted.minimized {
            let _ = booted.app.take_damage();
            repaint(booted, peers, request_id);
        }
        let interval = booted.app.tick_interval_ms().max(0);
        let now = mk_uptime_ms();
        let since = last_tick.map_or(interval, |t| now.saturating_sub(t));
        if since < 0 || since >= interval {
            last_tick = Some(now);
            if booted.app.on_tick() && !booted.minimized {
                repaint(booted, peers, request_id);
            }
        }
        let now = mk_uptime_ms();
        let since = last_tick.map_or(0, |t| now.saturating_sub(t).max(0));
        let retrying = !booted.primed || !booted.input_ready;
        let ms = pace::wait_ms(
            interval.saturating_sub(since),
            beat_left(booted, now),
            retrying,
            booted.app.busy(),
        );
        if let Some(held) = pace::block(rx, ms, booted.held.is_some()) {
            booted.held = Some(held);
        }
    }
}
