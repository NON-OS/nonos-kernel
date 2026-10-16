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

//! A tab strip's natural widths, which its size and its layout share.

use alloc::vec::Vec;

use super::Tabs;
use crate::design::scale::scale;
use crate::design::size::{SPACE, TABS_H};
use crate::design::text_role::TextRole;
use crate::widgets::text;

impl Tabs<'_> {
    /// Every tab at its natural width with `SPACE.xs` between them, by
    /// `TABS_H`.
    pub fn size(&self) -> (u32, u32) {
        (self.span(&self.widths()), scale().px(TABS_H))
    }

    /// The body text size the labels are drawn at.
    pub(super) fn px() -> f32 {
        scale().font(TextRole::Body.px())
    }

    /// Each tab's natural width: its label plus `SPACE.md` each side.
    pub(super) fn widths(&self) -> Vec<u32> {
        let pad = scale().px(u32::from(SPACE.md)).saturating_mul(2);
        let px = Self::px();
        self.labels.iter().map(|l| text::width(l, px).saturating_add(pad)).collect()
    }

    /// The width `widths` take laid end to end with the gaps between them.
    pub(super) fn span(&self, widths: &[u32]) -> u32 {
        let n = u32::try_from(widths.len().saturating_sub(1)).unwrap_or(u32::MAX);
        let gaps = scale().px(u32::from(SPACE.xs)).saturating_mul(n);
        widths.iter().fold(gaps, |sum, w| sum.saturating_add(*w))
    }
}
