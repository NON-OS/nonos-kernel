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

//! No-Op command TRB. Issuing one of these via the command ring
//! and waiting for a Command Completion Event with `CC_SUCCESS`
//! is the controller-bring-up smoke proof: it exercises producer
//! cycle, doorbell, controller fetch, completion event, ERDP
//! advance, and IMAN.IP clear all in one path.

use crate::constants::TRB_TYPE_NOOP_CMD;
use crate::trb::base::Trb;

pub fn noop_command(cycle: bool) -> Trb {
    let mut trb = Trb::zero();
    trb.set_type(TRB_TYPE_NOOP_CMD);
    trb.set_cycle(cycle);
    trb
}
