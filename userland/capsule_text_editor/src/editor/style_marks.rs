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

//! The formatting the ribbon applies, held beside the text it applies to.
//!
//! The document model is rebuilt from the text buffer on every edit, and the
//! text carries headings (a leading `#`) but no bold, italic, colour, font or
//! size. Those used to be written into the model alone, so the next keystroke
//! rebuilt it and they were gone; Export rebuilt it too, so no exported file
//! ever carried them. Each byte of the buffer now has a `Mark`, moved with the
//! text by the one edit path (`splice`), and each line an alignment, and the
//! rebuild lays both back over the fresh model.
//!
//! A mark names only what the ribbon set; everything it leaves alone comes
//! from the block, so a heading keeps its heading size until a size is chosen.
//! Typed text takes the mark of the character before it, as it does in any
//! word processor. Save writes the text alone, so formatting lives with the
//! open document and leaves it through Export.

use alloc::vec::Vec;

use super::state::State;
use crate::doc::align::Align;
use crate::doc::restyle::set_style;
use crate::doc::style::{Family, RunStyle, INK_ACCENT, INK_TEXT};

/// One character's formatting as the ribbon set it; `None` is "as the block".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Mark {
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub underline: Option<bool>,
    pub strike: Option<bool>,
    /// The ribbon's colour toggle: the theme accent, or back to body ink.
    pub accent: Option<bool>,
    pub family: Option<Family>,
    /// Point size in px, as the ribbon's size list offers it.
    pub size: Option<u8>,
}

impl Mark {
    /// `style` with this mark laid over it.
    pub fn apply(&self, style: &mut RunStyle) {
        if let Some(on) = self.bold {
            style.bold = on;
        }
        if let Some(on) = self.italic {
            style.italic = on;
        }
        if let Some(on) = self.underline {
            style.underline = on;
        }
        if let Some(on) = self.strike {
            style.strike = on;
        }
        if let Some(on) = self.accent {
            style.color = if on { INK_ACCENT } else { INK_TEXT };
        }
        if let Some(family) = self.family {
            style.family = family;
        }
        if let Some(px) = self.size {
            style.size_px = px as f32;
        }
    }
}

fn lines_in(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b == b'\n').count()
}

impl State {
    /// Forget all formatting: a new text was loaded into this document.
    pub fn reset_styles(&mut self) {
        self.marks.clear();
        self.marks.resize(self.len, Mark::default());
        self.aligns.clear();
        self.aligns.resize(lines_in(&self.buf[..self.len]) + 1, Align::Left);
    }

    /// Keep marks and alignments on the text they belong to across one splice:
    /// `removed` came out at `at` and `inserted` bytes went in. Called with
    /// the buffer already changed.
    pub(super) fn shift_styles(&mut self, at: usize, removed: &[u8], inserted: usize) {
        let old_len = self.len + removed.len() - inserted;
        if self.marks.len() != old_len {
            self.marks.resize(old_len, Mark::default());
        }
        let end = (at + removed.len()).min(self.marks.len());
        let at = at.min(end);
        let carry = match at {
            0 => self.marks.get(end).copied().unwrap_or_default(),
            _ => self.marks[at - 1],
        };
        self.marks.splice(at..end, core::iter::repeat_n(carry, inserted));

        let line = lines_in(&self.buf[..at]);
        let gone = lines_in(removed);
        let added = lines_in(&self.buf[at..at + inserted]);
        let lines = lines_in(&self.buf[..self.len]) + 1;
        if self.aligns.len() != lines + gone - added {
            self.aligns.resize(lines + gone - added, Align::Left);
        }
        let here = self.aligns.get(line).copied().unwrap_or(Align::Left);
        let from = (line + 1).min(self.aligns.len());
        let to = (line + 1 + gone).min(self.aligns.len());
        self.aligns.splice(from..to, core::iter::repeat_n(here, added));
        self.aligns.resize(lines, Align::Left);
    }

    /// Change the marks of buffer bytes `start..end`. False when the range is
    /// empty, so the caller can say a selection is needed.
    pub fn mark_range(&mut self, start: usize, end: usize, f: &dyn Fn(&mut Mark)) -> bool {
        let end = end.min(self.len);
        if start >= end {
            return false;
        }
        if self.marks.len() != self.len {
            self.marks.resize(self.len, Mark::default());
        }
        for m in &mut self.marks[start..end] {
            f(m);
        }
        self.reflow();
        true
    }

    /// Align every line that `start..end` touches.
    pub fn align_lines(&mut self, start: usize, end: usize, align: Align) {
        let first = lines_in(&self.buf[..start.min(self.len)]);
        let last = lines_in(&self.buf[..end.min(self.len)]);
        let lines = lines_in(&self.buf[..self.len]) + 1;
        if self.aligns.len() != lines {
            self.aligns.resize(lines, Align::Left);
        }
        for a in &mut self.aligns[first..=last.min(lines - 1)] {
            *a = align;
        }
        self.reflow();
    }

    /// Whether anything in the document carries formatting that Save leaves out.
    pub fn has_formatting(&self) -> bool {
        self.marks.iter().any(|m| *m != Mark::default())
            || self.aligns.iter().any(|a| *a != Align::Left)
    }

    /// Lay the marks and alignments over a model fresh from `doc_from_text`.
    /// Line `i` of the buffer is block `i`; a heading's `#` prefix is not in
    /// the block's text, so its marks start past it.
    pub(super) fn apply_styles(&mut self) {
        let text = &self.buf[..self.len];
        let mut base = 0usize;
        let starts: Vec<(usize, usize)> = text
            .split(|&b| b == b'\n')
            .map(|line| {
                let at = base;
                base += line.len() + 1;
                (at, line.len())
            })
            .collect();
        for (i, block) in self.doc.blocks.iter_mut().enumerate() {
            if let Some(a) = self.aligns.get(i) {
                block.align = *a;
            }
            let Some(&(line_at, line_len)) = starts.get(i) else { continue };
            let skip = line_len.saturating_sub(block.text.len());
            let from = line_at + skip;
            let to = (from + block.text.len()).min(self.marks.len());
            let mut run = from;
            while run < to {
                let mark = self.marks[run];
                let mut next = run + 1;
                while next < to && self.marks[next] == mark {
                    next += 1;
                }
                if mark != Mark::default() {
                    set_style(block, run - from, next - run, &|s| mark.apply(s));
                }
                run = next;
            }
        }
    }
}
