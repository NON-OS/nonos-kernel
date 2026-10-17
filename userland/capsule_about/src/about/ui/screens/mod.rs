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

mod append;
mod chain;
mod prose;
mod prose_wrap;
mod runtime_text;
mod tile_text;

mod display_surface;
mod licenses_banner;
mod licenses_cols;
mod licenses_table;
mod licenses_text;
mod overview_cards;
mod overview_hero;
mod overview_mark;
mod overview_tiles;
mod proofs_network;
mod proofs_route;
mod proofs_session;
mod proofs_verdict;
mod system_build;
mod system_runtime;
mod system_space;
mod system_uptime;
mod trust_caps;
mod trust_caps_list;
mod trust_chain;
mod trust_hops;
mod trust_pills;
mod verify_boot;
mod verify_boot_body;
mod verify_census;
mod verify_doc;
mod verify_doc_body;
mod verify_doc_cover;
mod verify_doc_rows;
mod verify_evidence;
mod verify_glyph;
mod verify_items;
mod verify_live;
mod verify_loader;
mod verify_mark;
mod verify_open;
mod verify_row;
mod verify_spawn;
mod verify_spawn_row;

pub mod display;
pub mod licenses;
pub mod overview;
pub mod proofs;
pub mod system;
pub mod trust;
pub mod verify;

mod extent;
pub use extent::content_h;
