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

//! The marketplace window's pure parts, mounted where the capsule keeps
//! them: the search, a listing and what is known of it, the order the
//! market is asked in, and install progress.

pub mod market {
    pub use nonos_market_proto::{App as Detail, Readiness, Release};
}

#[path = "../../../capsule_app_store/src/store/search.rs"]
pub mod search;

#[path = "../../../capsule_app_store/src/store/listing.rs"]
pub mod listing;

#[path = "../../../capsule_app_store/src/store/tab.rs"]
pub mod tab;

#[path = "../../../capsule_app_store/src/store/progress.rs"]
pub mod progress;

#[path = "../../../capsule_app_store/src/store/fill_order.rs"]
pub mod fill_order;

#[path = "../../../capsule_app_store/src/store/next_step.rs"]
pub mod next_step;

/* What the status line says when the system refuses a request outright. */
#[path = "../../../capsule_app_store/src/store/refused.rs"]
pub mod refused;

/* What the catalogue pane says when the market brought nothing back. */
#[path = "../../../capsule_app_store/src/store/market/failure.rs"]
pub mod failure;

/* Where the pointer is and what a click there acts on, over a stand-in for
 * the window's state. */
pub mod state;
pub mod ui;
