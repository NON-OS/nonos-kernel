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

mod cmd_file;
mod cmd_link;
mod cmd_misc;
mod cmd_mkdir;
mod cmd_perms;
mod cmd_rm;
mod env;
mod execute;
mod helpers;
mod run;
mod types;

pub use run::{run_post_install, run_post_remove, run_pre_install, run_pre_remove};
pub use types::{PostInstallHook, PostRemoveHook, PreInstallHook, PreRemoveHook};
