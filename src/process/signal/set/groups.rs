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

use super::bits::SignalSet;
use crate::process::signal::constants::{SIGKILL, SIGRTMAX, SIGRTMIN, SIGSTOP};

impl SignalSet {
    pub fn standard_signals() -> Self {
        let mut set = Self::empty();
        for signo in 1..SIGRTMIN {
            set.add(signo);
        }
        set
    }

    pub fn realtime_signals() -> Self {
        let mut set = Self::empty();
        for signo in SIGRTMIN..=SIGRTMAX {
            set.add(signo);
        }
        set
    }

    pub fn uncatchable() -> Self {
        let mut set = Self::empty();
        set.add(SIGKILL);
        set.add(SIGSTOP);
        set
    }
}
