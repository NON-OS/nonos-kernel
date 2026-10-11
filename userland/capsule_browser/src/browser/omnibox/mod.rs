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

//! The browser chrome's decisions, kept free of the capsule runtime so the
//! host proofs compile them unchanged: text editing and key mapping for the
//! address bar, focus routing, session history, what typed text and a
//! clicked link mean, scrolling, damage and the toolbar geometry.

mod areas;
mod band;
mod blit;
mod classify;
mod classify_host;
mod classify_scheme;
mod damage;
mod damage_map;
mod edit_key;
mod edit_key_map;
mod focus;
pub mod geometry;
mod history;
mod history_move;
mod hover;
mod line_delete;
mod line_edit;
mod line_move;
mod line_select;
mod link_action;
#[cfg(test)]
pub mod parts;
mod query_encode;
mod rect;
#[cfg(test)]
mod restyle;
mod rows;
mod scroll;
mod text_char;
mod text_offset;
mod word;

pub use band::band_safe;
pub use blit::{blit_plan, guarded, Blit};
pub use classify::{classify, Nav};
pub use damage::Damage;
pub use damage_map::{bits, rect_of, Change};
pub use edit_key::EditKey;
pub use edit_key_map::edit_key;
pub use focus::{focus_after, route, Focus, Region, Route};
pub use history::History;
pub use hover::{hover_update, should_commit};
pub use line_edit::{LineEdit, MAX_LEN};
pub use link_action::{link_action, same_document, LinkAction};
pub use rows::extend_rows;
pub use scroll::{scroll_to, ScrollAct};
pub use text_char::text_char;
pub use text_offset::text_offset;
