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

pub mod alarm;
pub mod clock;
pub mod constants;
pub mod interval;
pub mod posix;
pub mod tick;
pub mod timerfd_stats;
pub mod timerfd_types;
pub mod timerfd_util;
pub mod types;
pub mod utime;

pub use alarm::handle_alarm;
pub use clock::{get_clock_time, handle_clock_getres, handle_clock_gettime, handle_clock_settime};
pub use constants::*;
pub use interval::{handle_getitimer, handle_setitimer};
pub use posix::{
    handle_timer_create, handle_timer_delete, handle_timer_getoverrun, handle_timer_gettime,
    handle_timer_settime,
};
pub use tick::timer_tick;
pub use timerfd_stats::{
    get_global_stats as get_timerfd_global_stats, reset_stats as reset_timerfd_stats,
    TimerfdGlobalStats,
};
pub use timerfd_types::{handle_timerfd_create, handle_timerfd_gettime, handle_timerfd_settime};
pub use timerfd_util::{
    close_timerfd, fd_to_timerfd_id, get_timerfd_info_for_poll, is_timerfd, timerfd_read,
};
pub use types::{Itimerspec, Itimerval, Sigevent, TimerFdPollInfo, Timespec, Timeval};
pub use utime::{handle_futimesat, handle_utime, handle_utimensat, handle_utimes};
