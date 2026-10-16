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

//! The marketplace window: the catalogue the market capsule serves, the three
//! namespaces it carries, and why any one listing can or cannot be installed
//! on this machine.

mod app;
mod event;
mod event_actions;
mod event_click;
mod event_keys;
mod event_rows;
mod event_search;
mod event_tab;
mod fetch_status;
mod fill;
mod fill_order;
pub(crate) mod install;
mod install_primary;
mod listing;
mod poll;
mod progress;
mod progress_text;
mod refused;
mod route_offer;
pub mod market;
mod manifest;
mod model_card;
mod model_weights;
mod next_step;
pub mod search;
mod state;
mod state_move;
mod state_refresh;
mod state_select;
mod state_window;
mod tab;
mod state_ops;
mod tone;
mod tier_fit;
mod machine;
mod ui;
mod verdict;

pub use app::Store;
