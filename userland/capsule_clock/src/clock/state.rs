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

use nonos_libc::mk_uptime_ms;
use nonos_libc::time::{mk_time_millis, RtcTime};
use nonos_toolkit::widgets::Pointer;

use crate::clock::civil;
use crate::clock::controls::Target;
use crate::clock::says::wall_ms;
use crate::clock::stopwatch::Stopwatch;
use crate::clock::tabs::Tab;
use crate::clock::timer::Timer;

pub struct State {
    pub rtc: RtcTime,
    /// Whether the kernel gave a wall-clock time on the last read; until it
    /// does, `rtc` is no time at all and the Clock tab says so.
    pub clock_ok: bool,
    /// The Set tab's answer to the last Apply, empty until there is one.
    pub set_note: &'static [u8],
    /// Milliseconds since boot, the stopwatch's and timer's time base.
    pub now_ms: u64,
    pub tab: Tab,
    pub sw: Stopwatch,
    pub timer: Timer,
    pub edit_hour: u8,
    pub edit_min: u8,
    /// The width the window was last painted at. The tab bar spans it and
    /// its presses are read against it, full screen as at the opening size.
    pub win_w: u32,
    /// The pointer over the window, and the control under it.
    pub pointer: Pointer,
    pub hover: Option<Target>,
}

impl State {
    pub fn new() -> Self {
        let mut s = State {
            rtc: RtcTime::default(),
            clock_ok: false,
            set_note: b"",
            now_ms: 0,
            tab: Tab::Clock,
            win_w: crate::clock::manifest::WIDTH,
            sw: Stopwatch::default(),
            timer: Timer::default(),
            edit_hour: 0,
            edit_min: 0,
            pointer: Pointer::new(),
            hover: None,
        };
        s.refresh();
        s
    }

    pub fn refresh(&mut self) {
        // The stopwatch and timer measure spans, so they read the monotonic
        // clock: it runs from boot whether or not a wall time is known (with
        // none they stood still at zero), and a time set on the Set tab no
        // longer moves a span already running.
        if let Ok(up) = u64::try_from(mk_uptime_ms()) {
            self.now_ms = up;
        }
        let Some(n) = wall_ms(mk_time_millis()) else {
            self.clock_ok = false;
            return;
        };
        self.clock_ok = true;
        let c = civil::from_unix_ms(n);
        self.rtc = RtcTime {
            year: c.year,
            month: c.month,
            day: c.day,
            hour: c.hour,
            minute: c.minute,
            second: c.second,
            _pad: 0,
        };
    }

    pub fn load_edit(&mut self) {
        self.edit_hour = self.rtc.hour;
        self.edit_min = self.rtc.minute;
        self.set_note = b"";
    }
}
