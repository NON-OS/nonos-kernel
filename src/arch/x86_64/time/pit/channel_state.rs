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

use super::mode::Mode;
use core::sync::atomic::{AtomicBool, AtomicU64};

#[derive(Debug)]
pub(super) struct ChannelState {
    pub(super) configured: bool,
    pub(super) mode: Mode,
    pub(super) divisor: u16,
    pub(super) frequency_hz: u32,
    pub(super) tick_count: AtomicU64,
    pub(super) oneshot_pending: AtomicBool,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            configured: false,
            mode: Mode::RateGenerator,
            divisor: 0,
            frequency_hz: 0,
            tick_count: AtomicU64::new(0),
            oneshot_pending: AtomicBool::new(false),
        }
    }
}
