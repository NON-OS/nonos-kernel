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

use nonos_toolkit::widgets::Pointer;

use super::data::admission::Admission;
use super::data::attest_doc::{request, Attestation};
use super::data::own;
use super::data::proofs::{read as read_proofs, Snapshot};
use super::section::{Section, SECTIONS};
use super::ui::metrics::SCROLL_STEP;

// Scroll is in pixels, not rows: the screens are cards and gauges of differing
// heights, so a row index no longer names a position on any of them. The frame
// funnel records the pane height and the active screen's content height on the
// way through, which is the only place both are known at once.
pub struct State {
    pub section: Section,
    pub scroll: u32,
    pub fb_w: u32,
    pub fb_h: u32,
    pub view_h: u32,
    pub content_h: u32,
    // The signed statement of what this machine is running. Asking costs a TPM
    // signature, so it is asked when the user opens the Verify screen and held
    // until the window closes: a document re-signed on every repaint would put
    // the TPM on the paint path for no gain in truth.
    pub attest: Attestation,
    // The live proof board, sampled when the screen opens and once a second
    // while it stays open, so painting it never waits on IPC.
    pub proofs: Option<Snapshot>,
    // The capability word the kernel recorded for this window, and how its
    // spawn gate admitted it. Read once at open: neither changes while the
    // process lives, and the Overview and Trust screens draw from these
    // rather than from what the build declared.
    pub held: Option<u64>,
    pub admission: Admission,
    /// The pointer over the window, and the sidebar entry under it.
    pub pointer: Pointer,
    pub hover: Option<Section>,
}

impl State {
    pub fn new() -> Self {
        State {
            section: Section::Overview,
            scroll: 0,
            fb_w: 0,
            fb_h: 0,
            view_h: 0,
            content_h: 0,
            attest: Attestation::NotAsked,
            proofs: None,
            held: own::held_mask(),
            admission: own::admission(),
            pointer: Pointer::new(),
            hover: None,
        }
    }
    pub fn record_extent(&mut self, view_h: u32, content_h: u32) {
        self.view_h = view_h;
        self.content_h = content_h;
        self.scroll = self.scroll.min(self.max_scroll());
    }
    pub fn max_scroll(&self) -> u32 {
        self.content_h.saturating_sub(self.view_h)
    }
    pub fn select(&mut self, section: Section) -> bool {
        if self.section == section {
            return false;
        }
        self.section = section;
        self.scroll = 0;
        // Opening the screen is the act that asks the machine to attest itself,
        // and it is asked once: a second visit shows the document from the first,
        // which is the honest thing since nothing about it has been re-checked.
        if section == Section::Verify && matches!(self.attest, Attestation::NotAsked) {
            self.attest = request();
        }
        if section == Section::Proofs {
            self.proofs = Some(read_proofs());
        }
        true
    }
    /// Take a fresh sample when the proof board is on screen. True when the
    /// window should repaint.
    pub fn refresh_proofs(&mut self) -> bool {
        if self.section != Section::Proofs {
            return false;
        }
        self.proofs = Some(read_proofs());
        true
    }
    pub fn select_next_section(&mut self) {
        let next = (self.section.index() + 1) % SECTIONS.len();
        self.select(SECTIONS[next]);
    }
    pub fn select_prev_section(&mut self) {
        let prev = (self.section.index() + SECTIONS.len() - 1) % SECTIONS.len();
        self.select(SECTIONS[prev]);
    }
    pub fn scroll_line_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(SCROLL_STEP);
    }
    pub fn scroll_line_down(&mut self) {
        self.scroll = (self.scroll + SCROLL_STEP).min(self.max_scroll());
    }
    pub fn scroll_page_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(self.view_h.max(SCROLL_STEP));
    }
    pub fn scroll_page_down(&mut self) {
        self.scroll = (self.scroll + self.view_h.max(SCROLL_STEP)).min(self.max_scroll());
    }
}
