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

mod get_state;
mod healthcheck;
mod poll_events;
mod seq;
mod status_map;
mod transport;
mod types;

pub(super) use transport::REPLY_INBOX;

pub use get_state::{get_state, RingState};
pub use healthcheck::healthcheck;
pub use poll_events::poll_events;
pub use types::KeyEvent;
