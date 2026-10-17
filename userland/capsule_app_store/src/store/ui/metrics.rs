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
// Every layout size in real pixels at 1x. The list is a column of cards
/*
 * rather than table rows: a row of one name reads as a database dump, and the
 * catalogue has a description and a publisher for every entry that were going
 * unshown.
 */

pub const WIN_W: u32 = 1000;
pub const WIN_H: u32 = 680;
pub const WIN_X: u32 = 188;
pub const WIN_Y: u32 = 52;

pub const PAD_X: u32 = 22;
pub const PAD_TOP: u32 = 18;
pub const HEAD_H: u32 = 44;
pub const TAB_H: u32 = 32;
/// Air between the tab strip and the first card.
pub const TAB_TO_LIST: u32 = 10;

/// The search field in the head band, right-aligned.
pub const SEARCH_W: u32 = 260;
pub const SEARCH_H: u32 = 26;

/// A card holds two lines of text over a tile, so it is tall enough for
/// both plus the breathing room that stops a list looking like a table.
pub const CARD_H: u32 = 64;
pub const CARD_GAP: u32 = 6;
pub const CARD_PAD: u32 = 14;
pub const TILE: u32 = 36;
pub const TILE_GAP: u32 = 14;
/// The scrollbar beside the list, this far right of the cards.
pub const SCROLL_GAP: u32 = 6;
pub const SCROLL_W: u32 = 3;

/// The action sits at a fixed width on the right so every card's button
/// starts at the same x and the eye can run straight down them.
pub const ACTION_W: u32 = 96;
pub const ACTION_H: u32 = 28;

pub const DETAIL_W: u32 = 332;
pub const DETAIL_PAD: u32 = 18;
pub const GATE_ROW_H: u32 = 24;

pub const STATUS_H: u32 = 28;
pub const STATUS_PAD_X: u32 = 16;

pub const TITLE_PX: f32 = 23.0;
pub const NAME_PX: f32 = 18.0;
pub const BODY_PX: f32 = 17.0;
pub const SMALL_PX: f32 = 17.0;
