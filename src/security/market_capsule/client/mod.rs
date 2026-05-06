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

mod get_app;
mod get_release;
mod healthcheck;
mod install_ready;
mod list_apps;
mod load_index;
mod seq;
mod status_map;
mod transport;

pub(super) use transport::REPLY_INBOX;

pub use get_app::{get_app, AppSummary};
pub use get_release::{get_release, ReleaseSummary};
pub use healthcheck::healthcheck;
pub use install_ready::{install_ready, InstallReadiness};
pub use list_apps::list_apps;
pub use load_index::load_index;
