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

pub mod constants;
pub mod detect;
mod ops;
pub mod state;
mod status;

pub use ops::{disable, enable, get_timeout, is_enabled, kick, set_timeout};
pub use status::{get_status, WatchdogStatus};
pub use constants::{TCO_RLD, TCO1_CNT, TCO1_STS, TCO2_STS};
pub use detect::detect_tco_watchdog;
pub use state::{ENABLED, LAST_KICK, TIMEOUT_MS};
