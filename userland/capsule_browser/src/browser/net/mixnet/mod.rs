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

mod call;
mod choice;
mod conv;
mod fault;
mod frames;
mod heard;
mod io;
mod pace;
mod refusal;
mod route;
mod status;
mod streams;
mod system_default;
mod way;
mod wire;

pub use choice::{choose, chosen, Network};
pub use conv::Broke;
pub use heard::{heard, silent_now};
pub use status::{still, Heard};
pub use io::{broke, new_tick, poll, recv, send, sending};
pub use route::{direct_allowed, leave_spare, room, set_routes, way, UNSET};
pub use streams::SPARE;
pub use system_default::from_system_default;
pub use way::{Routes, Way};
pub use wire::{close, is_proxied, open, PROXIED};
