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

mod types;
mod run;
mod env;
mod execute;
mod helpers;
mod cmd_mkdir;
mod cmd_rm;
mod cmd_file;
mod cmd_link;
mod cmd_perms;
mod cmd_misc;

pub use types::{PreInstallHook, PostInstallHook, PreRemoveHook, PostRemoveHook};
pub use run::{run_pre_install, run_post_install, run_pre_remove, run_post_remove};
