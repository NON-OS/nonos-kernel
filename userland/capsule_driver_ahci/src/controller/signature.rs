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

use crate::constants::port::{PORT_KIND_ATAPI, PORT_KIND_PM, PORT_KIND_SEMB};
use crate::constants::{PORT_KIND_SATA, SIG_ATAPI, SIG_PM, SIG_SATA, SIG_SEMB};

pub fn classify(sig: u32) -> u8 {
    match sig {
        SIG_SATA => PORT_KIND_SATA,
        SIG_ATAPI => PORT_KIND_ATAPI,
        SIG_SEMB => PORT_KIND_SEMB,
        SIG_PM => PORT_KIND_PM,
        _ => crate::constants::port::PORT_KIND_UNKNOWN,
    }
}
