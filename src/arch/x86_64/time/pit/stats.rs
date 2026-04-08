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

#[derive(Debug, Clone, Default)]
pub struct PitStatistics {
    pub initialized: bool,
    pub channel0_frequency: u32,
    pub channel0_divisor: u16,
    pub channel0_ticks: u64,
    pub channel2_frequency: u32,
    pub channel2_divisor: u16,
    pub calibrations: u64,
    pub last_calibration_hz: u64,
    pub speaker_beeps: u64,
    pub oneshot_completed: u64,
}
