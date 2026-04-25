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

use super::structure::IoQueue;

impl IoQueue {
    #[inline]
    pub fn qid(&self) -> u16 {
        self.pair.qid()
    }
    #[inline]
    pub fn queue_id(&self) -> u16 {
        self.pair.qid()
    }
    #[inline]
    pub fn cq_id(&self) -> u16 {
        self.associated_cq_id
    }
    #[inline]
    pub fn sq_phys(&self) -> u64 {
        self.pair.sq_phys()
    }
    #[inline]
    pub fn cq_phys(&self) -> u64 {
        self.pair.cq_phys()
    }
    #[inline]
    pub fn sq_depth(&self) -> u16 {
        self.pair.sq_depth()
    }
    #[inline]
    pub fn cq_depth(&self) -> u16 {
        self.pair.cq_depth()
    }
    pub fn set_timeout(&self, spins: u32) {
        self.pair.set_timeout(spins);
    }
    pub fn pending_count(&self) -> u16 {
        self.pair.pending_count()
    }
    pub fn reset(&self) {
        self.pair.reset();
    }
}
