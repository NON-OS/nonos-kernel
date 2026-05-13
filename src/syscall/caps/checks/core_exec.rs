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

use crate::capabilities::{Capability, CapabilityToken};

impl CapabilityToken {
    #[inline]
    pub fn can_exit(&self) -> bool {
        self.grants(Capability::CoreExec) && self.is_valid()
    }
    #[inline]
    pub fn can_getpid(&self) -> bool {
        self.grants(Capability::CoreExec) && self.is_valid()
    }
    #[inline]
    pub fn can_fork(&self) -> bool {
        self.grants(Capability::CoreExec) && self.is_valid()
    }
    #[inline]
    pub fn can_exec(&self) -> bool {
        self.grants(Capability::CoreExec) && self.is_valid()
    }
    #[inline]
    pub fn can_wait(&self) -> bool {
        self.grants(Capability::CoreExec) && self.is_valid()
    }
    #[inline]
    pub fn can_signal(&self) -> bool {
        self.grants(Capability::CoreExec) && self.is_valid()
    }
}
