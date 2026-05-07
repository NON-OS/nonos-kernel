// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::{DIRECTMAP_BASE, DIRECTMAP_SIZE};

// phys -> directmap virt. Anything past the 256 GiB window is an
// error; we don't silently wrap.
pub fn phys_to_directmap_virt(phys: u64) -> Result<u64, &'static str> {
    if phys >= DIRECTMAP_SIZE {
        return Err("phys_to_directmap_virt: phys outside 256 GiB directmap window");
    }
    Ok(DIRECTMAP_BASE + phys)
}
