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

use super::rsb::rsb_fill;
use super::ibrs::ibrs_enable;
use super::ibpb::ibpb;
use super::mds::mds_clear;

#[inline(always)]
pub fn kernel_entry_mitigations() {
    rsb_fill();
    ibrs_enable();
}

#[inline(always)]
pub fn kernel_exit_mitigations() {
    mds_clear();
}

#[inline(always)]
pub fn context_switch_mitigations() {
    ibpb();
    rsb_fill();
}
