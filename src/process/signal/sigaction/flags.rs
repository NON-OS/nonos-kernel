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

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct SigactionFlags: u32 {
        const NOCLDSTOP = 0x00000001;
        const NOCLDWAIT = 0x00000002;
        const SIGINFO   = 0x00000004;
        const ONSTACK   = 0x08000000;
        const RESTART   = 0x10000000;
        const NODEFER   = 0x40000000;
        const RESETHAND = 0x80000000;
        const RESTORER  = 0x04000000;
    }
}
