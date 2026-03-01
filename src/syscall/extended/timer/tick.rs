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

use super::constants::SIGEV_SIGNAL;
use super::clock::get_clock_time;
use super::posix::POSIX_TIMERS;
use super::interval::INTERVAL_TIMERS;

pub fn timer_tick() {
    {
        let mut timers = POSIX_TIMERS.lock();
        for timer in timers.values_mut() {
            if !timer.armed || timer.expire_time == 0 {
                continue;
            }

            let now = get_clock_time(timer.clock_id);
            if now >= timer.expire_time {
                if timer.notify_type == SIGEV_SIGNAL {
                    crate::process::signal::send_signal(timer.owner_pid, timer.signal as u32);
                }

                if timer.interval > 0 {
                    let elapsed = now - timer.expire_time;
                    let overruns = (elapsed / timer.interval) as i32;
                    timer.overrun = overruns;
                    timer.expire_time += timer.interval * ((overruns + 1) as u64);
                } else {
                    timer.armed = false;
                }
            }
        }
    }

    {
        let mut timers = INTERVAL_TIMERS.lock();
        let now_usec = crate::time::timestamp_micros();

        for (&pid, proc_timers) in timers.iter_mut() {
            if let Some(ref mut timer) = proc_timers.real {
                let elapsed = now_usec - timer.start_time;
                if elapsed >= timer.expire_time {
                    crate::process::signal::send_signal(pid, 14);

                    if timer.interval > 0 {
                        timer.expire_time += timer.interval;
                        timer.start_time = now_usec;
                    } else {
                        proc_timers.real = None;
                    }
                }
            }
        }
    }
}
