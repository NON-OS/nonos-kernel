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


//! The market capsule's readiness gate, included and exercised.

extern crate alloc;

pub mod install_ready;

#[path = "../../capsule_market/src/server/handlers/install_ready/find_release.rs"]
pub mod find_release;

// The request header decode every frame passes before dispatch; the rest of
// the module is the capsule's reply side, which nothing here sends.
#[allow(dead_code, unused_imports)]
#[path = "../../capsule_market/src/protocol/mod.rs"]
mod protocol;

#[cfg(test)]
mod index_decode_tests;

pub mod release_wire;

pub mod store;

pub mod linux_why;

#[cfg(test)]
mod reason_tests;

pub mod terminal;

#[cfg(test)]
mod readiness_tests;

#[cfg(test)]
mod release_tests;

#[cfg(test)]
mod request_tests;

#[cfg(test)]
mod store_tests;

#[cfg(test)]
mod store_hover_box_tests;

#[cfg(test)]
mod store_hover_tests;

#[cfg(test)]
mod store_step_tests;

#[cfg(test)]
mod store_words_tests;

#[cfg(test)]
mod store_tab_strip_tests;

#[cfg(test)]
mod store_tab_tests;

#[cfg(test)]
mod wire_tests;
