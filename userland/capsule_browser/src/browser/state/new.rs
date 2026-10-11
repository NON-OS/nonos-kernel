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

use alloc::string::String;
use alloc::vec::Vec;

use super::{Chrome, PaintTrack, State, View};
use crate::browser::manifest::{HEIGHT, WIDTH};
use crate::browser::ui::layout::{compute, SidebarMode};

impl State {
    pub fn new() -> Self {
        let layout = compute(WIDTH as i32, HEIGHT as i32, SidebarMode::default());
        State {
            status: String::from("ready"),
            pending_nav: None,
            document: None,
            box_doc: None,
            page_dom: None,
            world: None,
            engine: None,
            settings_open: false,
            focus: None,
            pending_post: None,
            scroll: 0,
            sockets_port: 0,
            view: View::Home,
            fetch: None,
            base: None,
            redirect_count: 0,
            suppress_history_push: false,
            retries: 0,
            anyone_retry: None,
            proxy: None,
            images: crate::browser::image::Store::new(),
            image_queue: Vec::new(),
            img_turn: false,
            keep: None,
            font_queue: Vec::new(),
            font_seen: Vec::new(),
            viewport_w: layout.content.w as u32,
            viewport_h: layout.content.h as u32,
            layout,
            on_start: true,
            title: String::new(),
            visited: None,
            css_queue: Vec::new(),
            style_hold: crate::browser::fetch::StyleHold::default(),
            page_css: String::new(),
            script_queue: Vec::new(),
            css_cache: None,
            pool: crate::browser::fetch::Pool::new(),
            ui: Chrome::new(),
            track: PaintTrack::new(),
            scope: Default::default(),
        }
    }
}
