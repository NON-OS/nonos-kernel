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

use super::flags::SigactionFlags;
use crate::process::signal::constants::{SIG_DFL, SIG_IGN};
use crate::process::signal::set::SignalSet;

#[derive(Debug, Clone)]
pub struct Sigaction {
    pub handler: usize,
    pub flags: SigactionFlags,
    pub mask: SignalSet,
    pub restorer: usize,
}

impl Default for Sigaction {
    fn default() -> Self {
        Self {
            handler: SIG_DFL,
            flags: SigactionFlags::empty(),
            mask: SignalSet::empty(),
            restorer: 0,
        }
    }
}

impl Sigaction {
    pub fn new(handler: usize, flags: SigactionFlags, mask: SignalSet) -> Self {
        Self { handler, flags, mask, restorer: 0 }
    }

    pub fn with_restorer(mut self, restorer: usize) -> Self {
        self.restorer = restorer;
        self.flags |= SigactionFlags::RESTORER;
        self
    }

    pub fn is_default(&self) -> bool {
        self.handler == SIG_DFL
    }

    pub fn is_ignored(&self) -> bool {
        self.handler == SIG_IGN
    }

    pub fn is_handler(&self) -> bool {
        self.handler != SIG_DFL && self.handler != SIG_IGN
    }
}
