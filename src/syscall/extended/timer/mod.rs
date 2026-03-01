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

pub mod constants;
pub mod types;
pub mod clock;
pub mod posix;
pub mod timerfd;
pub mod interval;
pub mod alarm;
pub mod utime;
pub mod tick;

pub use constants::*;
pub use types::{Timespec, Itimerspec, Itimerval, Timeval, Sigevent, TimerFdPollInfo};
pub use clock::{handle_clock_gettime, handle_clock_settime, handle_clock_getres, get_clock_time};
pub use posix::{handle_timer_create, handle_timer_settime, handle_timer_gettime, handle_timer_getoverrun, handle_timer_delete};
pub use timerfd::{handle_timerfd_create, handle_timerfd_settime, handle_timerfd_gettime, timerfd_read, get_timerfd_info_for_poll, is_timerfd, fd_to_timerfd_id, close_timerfd};
pub use interval::{handle_getitimer, handle_setitimer};
pub use alarm::handle_alarm;
pub use utime::{handle_utime, handle_utimes, handle_utimensat, handle_futimesat};
pub use tick::timer_tick;
