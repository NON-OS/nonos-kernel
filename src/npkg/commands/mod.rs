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

mod info;
mod install;
mod list;
mod misc;
mod output;
mod remove;
mod search;
mod upgrade;

pub use info::cmd_info;
pub use install::cmd_install;
pub use list::cmd_list;
pub use misc::{cmd_clean, cmd_files, cmd_owner, cmd_stats, cmd_sync, cmd_verify};
pub use remove::cmd_remove;
pub use search::cmd_search;
pub use upgrade::cmd_upgrade;
