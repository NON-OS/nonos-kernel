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

pub mod install;
pub mod remove;
mod upgrade;
mod search;
mod info;
mod list;
mod tap_cmd;
mod doctor_cmd;
mod outdated;
mod deps;
mod clean;
mod pin;

pub use install::cmd_install;
pub use remove::cmd_remove;
pub use upgrade::{cmd_upgrade, cmd_upgrade_all};
pub use search::cmd_search;
pub use info::cmd_info;
pub use list::{cmd_list, cmd_leaves};
pub use tap_cmd::{cmd_tap, cmd_untap, cmd_taps};
pub use doctor_cmd::cmd_doctor;
pub use outdated::cmd_outdated;
pub use deps::cmd_deps;
pub use clean::cmd_clean;
pub use pin::{cmd_pin, cmd_unpin};
