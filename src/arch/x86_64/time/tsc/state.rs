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

pub use super::globals::{CALIBRATED, FEATURES, CALIBRATION, PER_CPU_TSC, STATS_RDTSC_CALLS, STATS_RDTSCP_CALLS};
pub use super::init_state::{init, init_with_hpet, is_initialized};
pub use super::stats_query::{is_calibrated, get_statistics, get_calibration_source, get_confidence};
