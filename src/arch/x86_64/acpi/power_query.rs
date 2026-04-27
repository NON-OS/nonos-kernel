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

use super::parser;
use super::power_types::SleepState;

pub fn is_sleep_state_supported(state: SleepState) -> bool {
    match state {
        SleepState::S0 => true,
        SleepState::S5 => parser::with_data(|data| data.pm1a_control != 0).unwrap_or(false),
        _ => false,
    }
}

pub fn current_profile() -> Option<super::tables::PmProfile> {
    parser::pm_profile()
}

pub fn is_server() -> bool {
    parser::pm_profile().map(|p| p.is_server()).unwrap_or(false)
}

pub fn is_mobile() -> bool {
    parser::pm_profile().map(|p| p.is_mobile()).unwrap_or(false)
}
