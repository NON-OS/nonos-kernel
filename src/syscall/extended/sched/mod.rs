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

pub mod affinity;
pub mod attr;
pub mod param;
pub mod prio;
pub mod util;

pub use util::{PRIO_PROCESS, PRIO_PGRP, PRIO_USER};

pub use param::{
    handle_sched_setparam, handle_sched_getparam,
    handle_sched_setscheduler, handle_sched_getscheduler,
    handle_sched_get_priority_max, handle_sched_get_priority_min,
    handle_sched_rr_get_interval,
};

pub use affinity::{handle_sched_setaffinity, handle_sched_getaffinity};

pub use attr::{handle_sched_setattr, handle_sched_getattr};

pub use prio::{
    handle_getpriority, handle_setpriority,
    handle_ioprio_set, handle_ioprio_get,
    handle_sched_yield,
};
