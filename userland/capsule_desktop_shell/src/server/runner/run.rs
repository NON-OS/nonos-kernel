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

use alloc::vec;

use nonos_libc::mk_uptime_ms;

use super::drain::drain;
use super::refresh_clock::refresh_clock;
use super::tick::{tick_due, wake_at};
use crate::protocol::{HDR_LEN, IPC_PAYLOAD_MAX};
use crate::render::sync_toast_layer;
use crate::server::refresh_taskbar::refresh_taskbar;
use crate::state::Context;

pub fn run(mut ctx: Context) -> ! {
    let _ = nonos_app_skeleton::runner::follow_theme();
    crate::server::paint_initial::paint_initial(&mut ctx);
    let mut rx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut tx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut last_tick_ms: i64 = mk_uptime_ms();
    refresh_clock(&mut ctx);
    loop {
        let toast_due = ctx.toasts.next_expiry().map(|t| t.0);
        drain(&mut ctx, &mut rx, &mut tx, wake_at(last_tick_ms, toast_due));
        if ctx.policy_gap.due(mk_uptime_ms().max(0) as u64)
            && nonos_app_skeleton::runner::follow_theme()
        {
            crate::server::repaint::repaint(&mut ctx);
        }
        // A menu, a dialog or the Launchpad opened or closed by what was just
        // handled takes or gives back the pointer here.
        crate::server::grabs::sync(&mut ctx);
        // A full-screen window shown or gone, or the pointer at the bottom
        // edge: the dock drawn or cleared, its window opened or closed.
        crate::server::dock_sync::sync(&mut ctx);
        /*
         * The tick is timed on the uptime clock. The wall clock can step back
         * when NTP corrects it, or read as an error before it is set, and a
         * tick timed on it then stopped for as long as the step: no clock, no
         * toasts expiring, no subscriptions retried.
         */
        let tick_ms = mk_uptime_ms();
        if tick_due(tick_ms, last_tick_ms) {
            refresh_clock(&mut ctx);
            if !ctx.input_ready {
                let port = ctx.input_router_port;
                crate::setup::subscribe_input(&mut ctx, port);
            }
            if !ctx.wm_notify_ready {
                let port = ctx.wm_port;
                crate::setup::subscribe_wm(&mut ctx, port);
            }
            /*
             * Keep the desktop icons in step with the filesystem, but only
             * when the store says something moved. Both listings below walk a
             * directory and copy it across an IPC boundary, and they used to do
             * that every second whether or not there was anything to find.
             */
            if crate::server::store_changed::since_last_look() {
                if crate::server::desktop::refresh(&mut ctx) {
                    crate::server::repaint::repaint(&mut ctx);
                }
                crate::server::packages::refresh(&mut ctx);
            }
            crate::server::wallpaper_policy::retry(&mut ctx);
            crate::server::installed_apps::load_once(&mut ctx);
            crate::server::store_health::check(&mut ctx);
            // Asks the policy store, so not while it is quiet (refresh_clock).
            if ctx.policy_gap.due(tick_ms.max(0) as u64) {
                crate::server::handlers::live_prompt::check(&mut ctx);
            }
            // A window whose process ended without its close reaching the
            // shell: the dock mark and the menubar's app name go with it.
            if crate::state::forget_dead_windows(&mut ctx.taskbar, |p| nonos_libc::mk_pid_alive(p))
                != 0
            {
                crate::server::repaint::repaint(&mut ctx);
            }
            // A launch whose window never came is said, not left as a dock
            // that did nothing.
            let dock_now = crate::server::dock_clock::now();
            crate::server::launch_overdue::say(&mut ctx, dock_now);
            let pulse_dirty = crate::state::expire_taskbar_pulses(&mut ctx.taskbar, dock_now);
            crate::state::expire_taskbar_visibility(&mut ctx.taskbar, dock_now);
            if pulse_dirty && ctx.taskbar.visible {
                refresh_taskbar(&mut ctx);
            }
            crate::server::dock_sync::sync(&mut ctx);
            last_tick_ms = tick_ms;
        }
        /*
         * The toasts, on every pass rather than on the tick: a toast whose
         * time is up leaves now, the loop having woken for it (`wake_at`),
         * and one pushed by any handler is put on screen now, whether or not
         * that handler synced the panel. The panel is synced only when the
         * queue moved, so a pass with nothing new costs one comparison.
         */
        ctx.toasts.expire(crate::server::toast_clock::now());
        if ctx.toasts_synced != ctx.toasts.generation() {
            sync_toast_layer(&mut ctx);
        }
        /*
         * No vsync sleep: drain() already blocks on the IPC inbox (waking the
         * instant an input or notify message arrives, and timing out every
         * RECV_BLOCK ms so the clock still ticks). Parking again on the vsync
         * tick only added up to a frame of latency to every click, since an
         * inbound event cannot preempt a vsync wait.
         */
    }
}
