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

use super::damage::Rect;
use super::scene::SceneTable;

// Drops every layer owned by `owner_pid` from the scene table and
// returns the union rectangle so the runner can mark it damaged.
// Returns None when the pid held no layers.
pub fn remove_by_pid(scene: &mut SceneTable, owner_pid: u32) -> Option<Rect> {
    let mut union: Option<Rect> = None;
    for layer in scene.layers().filter(|l| l.owner_pid == owner_pid) {
        let r = Rect { x: layer.x, y: layer.y, width: layer.width, height: layer.height };
        union = Some(match union {
            None => r,
            Some(u) => {
                let x0 = core::cmp::min(u.x, r.x);
                let y0 = core::cmp::min(u.y, r.y);
                let x1 = core::cmp::max(u.x + u.width, r.x + r.width);
                let y1 = core::cmp::max(u.y + u.height, r.y + r.height);
                Rect { x: x0, y: y0, width: x1 - x0, height: y1 - y0 }
            }
        });
    }
    if union.is_some() {
        scene.drop_by_pid(owner_pid);
    }
    union
}
