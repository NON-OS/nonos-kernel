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

mod clean;
mod deps;
mod doctor_cmd;
mod info;
pub mod install;
mod list;
mod outdated;
mod pin;
pub mod remove;
mod search;
mod tap_cmd;
mod upgrade;

pub use clean::cmd_clean;
pub use deps::cmd_deps;
pub use doctor_cmd::cmd_doctor;
pub use info::cmd_info;
pub use install::cmd_install;
pub use list::{cmd_leaves, cmd_list};
pub use outdated::cmd_outdated;
pub use pin::{cmd_pin, cmd_unpin};
pub use remove::cmd_remove;
pub use search::cmd_search;
pub use tap_cmd::{cmd_tap, cmd_taps, cmd_untap};
pub use upgrade::{cmd_upgrade, cmd_upgrade_all};
