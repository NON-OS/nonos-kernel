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

use super::state::MSI_CLAIMED;

pub fn claim_gsi_for_msi(gsi: u32) {
    let mut claimed = MSI_CLAIMED.lock();
    if (gsi as usize) < claimed.len() {
        claimed.set(gsi as usize, true);
    }
}

pub fn release_gsi_from_msi(gsi: u32) {
    let mut claimed = MSI_CLAIMED.lock();
    if (gsi as usize) < claimed.len() {
        claimed.set(gsi as usize, false);
    }
}

pub(super) fn is_gsi_claimed(gsi: u32) -> bool {
    let claimed = MSI_CLAIMED.lock();
    (gsi as usize) < claimed.len() && claimed[gsi as usize]
}
