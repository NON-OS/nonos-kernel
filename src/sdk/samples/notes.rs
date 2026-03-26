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

use alloc::vec::Vec;
use crate::sdk::app::{App, AppContext, AppEvent, AppResult};
use crate::sdk::storage::AppStorage;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};
use crate::graphics::font::draw_char;

pub struct NotesApp {
    notes: Vec<Vec<u8>>,
    current: Vec<u8>,
    storage: Option<AppStorage>,
}

impl NotesApp {
    pub fn new() -> Self { Self { notes: Vec::new(), current: Vec::new(), storage: None } }

    fn draw_text(&self, x: u32, y: u32, text: &[u8], color: u32) {
        for (i, &c) in text.iter().enumerate() { draw_char(x + i as u32 * 8, y, c, color); }
    }
}

impl App for NotesApp {
    fn id(&self) -> &str { "notes" }
    fn name(&self) -> &str { "Notes" }
    fn version(&self) -> &str { "1.0.0" }

    fn init(&mut self, ctx: &AppContext) -> AppResult<()> {
        self.storage = Some(AppStorage::new(ctx.app_id));
        if let Some(ref s) = self.storage {
            if let Some(data) = s.get(b"notes") { self.notes = parse_notes(&data); }
        }
        Ok(())
    }

    fn render(&self, ctx: &AppContext) {
        fill_rect(ctx.x, ctx.y, ctx.width, ctx.height, 0xFF14141C);
        self.draw_text(ctx.x + 20, ctx.y + 20, b"Notes", 0xFFFFFFFF);
        fill_rounded_rect(ctx.x + 20, ctx.y + 50, ctx.width - 40, 36, 6, 0xFF1E1E28);
        for (i, c) in self.current.iter().take(40).enumerate() {
            draw_char(ctx.x + 28 + i as u32 * 8, ctx.y + 60, *c, 0xFFFFFFFF);
        }
        let mut ny = ctx.y + 100;
        for note in self.notes.iter().take(8) {
            fill_rounded_rect(ctx.x + 20, ny, ctx.width - 40, 30, 6, 0xFF1A1A24);
            let len = note.len().min(40);
            self.draw_text(ctx.x + 28, ny + 8, &note[..len], 0xFFCCCCCC);
            ny += 36;
        }
    }

    fn handle_event(&mut self, _ctx: &AppContext, event: AppEvent) -> AppResult<bool> {
        if let AppEvent::Key(ch) = event {
            if ch == 13 && !self.current.is_empty() {
                self.notes.insert(0, self.current.clone());
                self.current.clear();
                self.save_notes();
                return Ok(true);
            } else if ch == 8 && !self.current.is_empty() {
                self.current.pop();
                return Ok(true);
            } else if ch >= 32 && ch < 127 && self.current.len() < 100 {
                self.current.push(ch);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn cleanup(&mut self) { self.save_notes(); }
}

impl NotesApp {
    fn save_notes(&self) {
        if let Some(ref s) = self.storage {
            let data = serialize_notes(&self.notes);
            s.set(b"notes", &data);
        }
    }
}

fn parse_notes(data: &[u8]) -> Vec<Vec<u8>> {
    data.split(|&b| b == b'\n').filter(|l| !l.is_empty()).map(|l| l.to_vec()).collect()
}

fn serialize_notes(notes: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    for n in notes { data.extend_from_slice(n); data.push(b'\n'); }
    data
}
