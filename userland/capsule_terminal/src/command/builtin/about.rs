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

use crate::command::output::Output;

pub fn run(out: &mut Output<'_>, _argv: &[&[u8]]) {
    out.writeln(b"NONOS terminal capsule: signed CPL=3 user binary.");
    out.writeln(b"speaks NCMP wire to compositor + wm for window + input.");
    out.writeln(b"speaks tag4 syscalls (MISD/MIRC/MICL/MSVL/MEXT/MYLD).");
    out.writeln(b"no shell fork. no fd. no ptys. native NONOS.");
}
