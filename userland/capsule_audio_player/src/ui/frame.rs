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

//! Frame composition. The ground cache is blitted first, then the chrome, then
//! whichever screen the current view names. Screens draw into `page`, which is
//! the content column inset by the layout's gutter.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::library::{Library, Queue};
use crate::model::PlayerView;
use crate::waveform::Waveform;

use super::geometry::{page, shell};
use super::icon::Icons;
use super::metrics::R_WIN;
use super::paint::stroke;
use super::screen;
use super::shell::{rail, sidebar, topbar, transport, Ground};
use super::state::{UiState, View};

pub struct Frame {
    pub icons: Icons,
    ground: Option<Ground>,
}

pub struct Scene<'a> {
    pub lib: &'a Library,
    pub queue: &'a Queue,
    pub rows: &'a [usize],
    pub view: &'a PlayerView,
    pub wave: &'a Waveform,
    pub playing: Option<usize>,
    pub id: &'a str,
    /// The output's level, for the playing row's meter.
    pub level: u16,
    /// The Downloads page's rows.
    pub downloads: &'a [crate::fetch::list::Row],
}

impl Frame {
    pub fn new() -> Frame {
        Frame { icons: Icons::new(), ground: None }
    }

    pub fn paint(&mut self, fb: &mut PaintBuffer, ui: &UiState, s: &Scene) {
        let (w, h) = (fb.width, fb.height);
        if !self.ground.as_ref().is_some_and(|g| g.fits(w, h)) {
            self.ground = Some(Ground::build(w as i32, h as i32));
        }
        if let Some(g) = &self.ground {
            g.blit(fb);
        }

        let sh = shell(w, h);
        stroke(fb, sh.frame, R_WIN, 1, roles().border.argb());
        sidebar(fb, &self.icons, sh.sidebar, ui.view);
        topbar(fb, &self.icons, sh.topbar, &ui.query, ui.view == View::Search);
        transport(fb, &self.icons, sh.transport, s.view, s.id);
        rail(fb, &self.icons, sh.rail, s.lib, s.queue, s.view);

        let p = page(&sh);
        match ui.view {
            View::Home => screen::home(fb, &self.icons, p, s.lib, s.playing),
            View::Library => screen::library(
                fb,
                &self.icons,
                p,
                s.lib,
                s.queue,
                s.rows,
                ui.lib_tab,
                ui.scroll,
                s.playing,
                ui.hover,
                s.level,
            ),
            View::Search => screen::search(
                fb,
                &self.icons,
                p,
                s.lib,
                s.queue,
                s.rows,
                &ui.query,
                ui.scroll,
                s.playing,
                ui.hover,
                s.level,
            ),
            View::Downloads => screen::downloads(fb, &self.icons, p, s.downloads, ui.scroll),
            View::NowPlaying => screen::nowplaying(fb, p, s.view, s.wave, s.id),
            View::Settings => screen::settings(fb, &self.icons, p, s.view, s.lib, s.queue),
        }
    }
}
