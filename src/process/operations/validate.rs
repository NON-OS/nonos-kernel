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

use super::super::clone_flags::*;

pub(crate) fn validate_clone_flags(flags: u64) -> bool {
    if (flags & CLONE_THREAD) != 0 && (flags & CLONE_SIGHAND) == 0 {
        return false;
    }
    if (flags & CLONE_SIGHAND) != 0 && (flags & CLONE_VM) == 0 {
        return false;
    }
    if (flags & CLONE_FS) != 0 && (flags & CLONE_NEWNS) != 0 {
        return false;
    }
    true
}
