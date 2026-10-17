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

//! Fixed sizes shared by every widget, in logical pixels.

use super::spacing::SpacingScale;

/// The spacing every widget uses.
pub const SPACE: SpacingScale = SpacingScale { xs: 4, sm: 8, md: 12, lg: 16, xl: 24 };
/// Corner radius of buttons and fields.
pub const CONTROL_RADIUS: u32 = 8;
/// Corner radius of cards. The window frame uses 12 as well.
/// A pill's radius is half its height and has no constant.
pub const CARD_RADIUS: u32 = 12;
/// Height of a list row.
pub const ROW_H: u32 = 44;
/// Height of a list row with a note line.
pub const ROW_NOTE_H: u32 = 66;
/// Side of the square a row's disclosure chevron is drawn in.
pub const CHEVRON: u32 = 8;
/// Height of a card's head when it holds only a title.
pub const CARD_HEAD_H: u32 = 48;
/// Height of a card's head when a note sits under the title.
pub const CARD_HEAD_NOTE_H: u32 = 74;
/// Gap between a title and the note line stacked under it.
pub const LINE_GAP: u32 = 2;
/// Height of the navigation bar.
pub const NAV_H: u32 = 38;
/// Side of the square a navigation item's icon is drawn in.
pub const ICON: u32 = 18;
/// Height of a field or button.
pub const CONTROL_H: u32 = 36;
/// Preferred width of a one-line text or search field.
pub const FIELD_W: u32 = 236;
/// Side of the square a field's icon is drawn in.
pub const FIELD_ICON: u32 = 14;
/// Height of a tab strip.
pub const TABS_H: u32 = 32;
/// Height of a pill.
pub const PILL_H: u32 = 26;
/// Space between a pill's edge and what it holds, each side.
pub const PILL_PAD: u32 = 11;
/// Widest a tooltip's box grows. A longer text is cut with `…` to fit.
pub const TOOLTIP_MAX_W: u32 = 320;
/// Widest a toast's panel grows. A longer text wraps to a second line.
pub const TOAST_W: u32 = 360;
/// Diameter of a pill's status dot.
pub const DOT: u32 = 7;
/// Width of a switch.
pub const SWITCH_W: u32 = 42;
/// Height of a switch.
pub const SWITCH_H: u32 = 24;
/// Gap between a switch's track and its knob.
pub const KNOB_INSET: u32 = 2;
/// Side of a checkbox's box and of a radio's ring.
pub const CHECK: u32 = 20;
/// The corner of a checkbox's box: a quarter of its side, so it reads as a
/// square beside a radio's ring.
pub const CHECK_RADIUS: u32 = 5;
/// Stroke of a checkbox's tick, at a box `CHECK` wide.
pub const TICK: u32 = 2;
/// Diameter of a radio's dot, at a ring `CHECK` wide.
pub const RADIO_DOT: u32 = 8;
/// Preferred width of a slider.
pub const SLIDER_W: u32 = 150;
/// Height of a slider's track.
pub const TRACK_H: u32 = 4;
/// Radius of a slider's knob.
pub const KNOB_R: u32 = 7;
/// Height of a progress bar.
pub const PROGRESS_H: u32 = 6;
/// Width of a scroll bar.
pub const SCROLL_W: u32 = 4;
/// Length of the shortest scroll thumb.
pub const SCROLL_MIN: u32 = 18;
