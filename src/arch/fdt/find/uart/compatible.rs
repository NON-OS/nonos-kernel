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

use crate::arch::fdt::property::Property;

use super::kind::UartKind;

// Inspect `compatible` for a UART variant we support.
pub fn classify(compat: &Property) -> Option<UartKind> {
    for s in compat.stringlist() {
        if s == b"arm,pl011" {
            return Some(UartKind::Pl011);
        }
        if s == b"ns16550a" || s == b"ns16550" {
            return Some(UartKind::Ns16550);
        }
    }
    None
}
