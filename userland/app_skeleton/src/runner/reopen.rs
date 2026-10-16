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

use crate::app::App;
use crate::clients::wm::WindowPlacement;
use crate::discover::Peers;
use crate::setup::reopen_surface;

use super::boot::BootedApp;
use super::paint_frame::paint;

/// Move the window onto a new surface at `placement`, drawn whole (frame and
/// content, `maximized` or not) before the compositor shows it, and keep it.
/// The submit that shows it repaints the old and new rectangles, so no damage
/// commit follows. False when the window keeps its old surface.
pub(super) fn reopen<A: App>(
    booted: &mut BootedApp<A>,
    peers: &Peers,
    request_id: &mut u32,
    placement: WindowPlacement,
    maximized: bool,
) -> bool {
    let hover = booted.drag.hover;
    let (app, manifest) = (&mut booted.app, &booted.manifest);
    let opened = reopen_surface(peers, &booted.binding, placement, request_id, |b| {
        paint(app, manifest, b, hover, maximized)
    });
    let Ok(binding) = opened else { return false };
    booted.binding = binding;
    booted.maximized = maximized;
    booted.painted = (placement.width, placement.height, hover, maximized);
    // The whole window was just drawn: what the app had marked is on it.
    let _ = booted.app.take_damage();
    true
}
