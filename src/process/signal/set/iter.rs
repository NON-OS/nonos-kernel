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

pub struct SignalSetIter {
    set: SignalSet,
    current: u8,
}

impl SignalSetIter {
    pub(super) fn new(set: SignalSet) -> Self {
        Self { set, current: 1 }
    }
}

impl Iterator for SignalSetIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current <= 64 {
            let signo = self.current;
            self.current += 1;
            if self.set.contains(signo) {
                return Some(signo);
            }
        }
        None
    }
}
