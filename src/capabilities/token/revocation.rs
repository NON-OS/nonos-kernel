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

extern crate alloc;

use alloc::collections::BTreeSet;
use spin::RwLock;

static REVOKED: RwLock<BTreeSet<(u64, u64)>> = RwLock::new(BTreeSet::new());

pub fn revoke_token(owner: u64, nonce: u64) {
    REVOKED.write().insert((owner, nonce));
}

#[inline]
pub fn is_revoked(owner: u64, nonce: u64) -> bool {
    REVOKED.read().contains(&(owner, nonce))
}

#[inline]
pub fn revoked_count() -> usize {
    REVOKED.read().len()
}

pub fn clear_revocations() {
    REVOKED.write().clear();
}

pub fn revoke_all_for_owner(owner: u64) {
    let mut revoked = REVOKED.write();
    let to_keep: BTreeSet<_> = revoked
        .iter()
        .filter(|(o, _)| *o != owner)
        .copied()
        .collect();
    *revoked = to_keep;
}
