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

use nonos_app_skeleton::{App, AppManifest, EventOutcome, InputEvent, InputKind, PaintBuffer};

use super::doc::Doc;
use super::draw::MARGIN;
use super::event::on_event;
use super::layout::{wrap, Line};
use super::manifest::manifest;
use super::measure::measure;
use super::paint::paint;
use super::scroll::{max_scroll, wheel};

pub struct MdView {
    doc: Doc,
    lines: Vec<Line>,
    wrapped_width: u32,
    /// How far the page is scrolled up, in pixels, and the window height it
    /// was last drawn in, which is what the wheel measures its end against.
    scroll: u32,
    view_h: u32,
}

impl MdView {
    pub fn new() -> Self {
        MdView {
            doc: Doc::new(),
            lines: Vec::new(),
            wrapped_width: 0,
            scroll: 0,
            view_h: 0,
        }
    }

    fn relayout(&mut self, width: u32) {
        let reloaded = self.doc.ensure();
        if self.doc.blocks.is_empty() || !(reloaded || self.wrapped_width != width) {
            return;
        }
        self.wrapped_width = width;
        let content = (width as i32 - 2 * MARGIN).max(80);
        self.lines = wrap(&self.doc.blocks, content, measure);
    }
}

impl App for MdView {
    fn manifest(&self) -> AppManifest {
        manifest()
    }

    fn on_event(&mut self, event: InputEvent) -> EventOutcome {
        /*
         * The page used to stop at the window's bottom edge with no way on;
         * the wheel now scrolls it.
         */
        if event.kind == InputKind::Wheel {
            let next = wheel(self.scroll, &self.lines, self.view_h, event.delta_y);
            if next == self.scroll {
                return EventOutcome::Idle;
            }
            self.scroll = next;
            return EventOutcome::Repaint;
        }
        on_event(event)
    }

    fn paint(&mut self, fb: &mut PaintBuffer) {
        self.relayout(fb.width);
        self.view_h = fb.height;
        self.scroll = self.scroll.min(max_scroll(&self.lines, fb.height));
        paint(fb, &self.lines, self.doc.error, self.scroll);
    }
}
