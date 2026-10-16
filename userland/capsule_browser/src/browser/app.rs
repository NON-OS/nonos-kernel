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

use nonos_app_skeleton::{App, AppManifest, EventOutcome, InputEvent, PaintBuffer};
use nonos_toolkit::decorations::Rect;

use super::manifest::manifest;

mod accessory;
mod browser;
mod cards;
mod damage;
mod dl_save;
mod downloads;
mod nav;
mod paint;
mod print;
mod pumps;
mod route;
mod strip;
mod theme;
mod tick;
mod tick_tabs;
mod visits;

pub use browser::Browser;

impl App for Browser {
    fn manifest(&self) -> AppManifest {
        manifest()
    }
    fn on_event(&mut self, event: InputEvent) -> EventOutcome {
        let out = self.route(event);
        self.retheme(out)
    }
    fn paint(&mut self, fb: &mut PaintBuffer) {
        self.shell.cards = cards::cards(&self.tabs);
        paint::paint_app(self.tabs.active_mut(), &self.shell, fb);
    }
    fn on_tick(&mut self) -> bool {
        let shown = tick_tabs::tick_tabs(&mut self.tabs, &mut self.shell, &mut self.cursor);
        let themed = self.rethemed();
        shown || themed || self.strip_moved()
    }

    fn tick_interval_ms(&self) -> i64 {
        50
    }

    /* A load still on its way in any tab must keep stepping: busy makes the
     * runner yield rather than sleep, so pages advance through their fetch
     * stages on their own instead of stalling until the pointer moves. */
    fn busy(&self) -> bool {
        self.tabs.list.iter().any(|s| s.loading())
    }

    /* Only a whole-window repaint draws the tab strip with the frame. */
    fn take_damage(&mut self) -> Option<Rect> {
        match self.strip_moved() {
            true => None,
            false => damage::take(self.tabs.active_mut()),
        }
    }

    fn titlebar_accessory_w(&self) -> u32 {
        self.accessory_w()
    }

    fn paint_accessory(&mut self, fb: &mut PaintBuffer) {
        self.paint_strip(fb);
    }

    fn on_accessory_event(&mut self, event: InputEvent) -> EventOutcome {
        self.strip_event(event)
    }
}
