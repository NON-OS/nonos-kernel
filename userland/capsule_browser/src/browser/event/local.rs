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

use nonos_app_skeleton::InputEvent;

use crate::browser::ui::rect::Rect;

/* `event` in the coordinates of `area`, its top left corner at (0, 0),
 * when the event lands inside it. Pointer events are translated here once,
 * so the toolbar and the page hit-test what they drew. */
pub(super) fn local(event: InputEvent, area: Rect) -> Option<InputEvent> {
    let at = InputEvent { x: event.x - area.x, y: event.y - area.y, ..event };
    area.contains(event.x, event.y).then_some(at)
}
