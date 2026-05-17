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

use nonos_libc::{mk_yield, nonos_display_dimensions};

use super::discover;
use crate::compositor_client::probe_compositor;
use crate::focus::FocusModel;
use crate::state::{Context, SubscriptionList};
use crate::window::WindowTable;
use crate::z_order::ZStack;

const READY_ATTEMPTS: usize = 256;

// Wait for the compositor service then read display dimensions
// through the graphics contract. Display is needed up front so the
// wm can clamp window geometry on every move/resize.
pub fn run() -> Result<Context, &'static str> {
    let mut last_err = "compositor unavailable";
    for _ in 0..READY_ATTEMPTS {
        match run_once() {
            Ok(ctx) => return Ok(ctx),
            Err(e) => {
                last_err = e;
                mk_yield();
            }
        }
    }
    Err(last_err)
}

fn run_once() -> Result<Context, &'static str> {
    let compositor_port = discover::lookup_compositor_port()?;
    probe_compositor(compositor_port, 1)?;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let rc = nonos_display_dimensions(0, &mut width as *mut u32, &mut height as *mut u32);
    if rc != 0 || width == 0 || height == 0 {
        return Err("display dimensions unavailable");
    }
    Ok(Context {
        compositor_port,
        display_width: width,
        display_height: height,
        windows: WindowTable::new(),
        focus: FocusModel::new(),
        z: ZStack::new(),
        subscriptions: SubscriptionList::new(),
        next_request_id: 1,
    })
}
