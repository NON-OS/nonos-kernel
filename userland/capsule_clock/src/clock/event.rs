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

use nonos_app_skeleton::EventOutcome;

use nonos_libc::time::mk_time_adjust;

use crate::clock::civil;
use crate::clock::controls::{target_at, Target};
use crate::clock::says::{adjust_outcome, NO_DATE};
use crate::clock::state::State;
use crate::clock::tabs::{all, Tab};

/// A click on whatever `target_at` names there: a tab, or a button of the tab
/// shown, by its place in `controls::keys`.
pub fn on_click(state: &mut State, x: i32, y: i32) -> EventOutcome {
    let key = match target_at(state.tab, state.win_w, x, y) {
        Some(Target::Tab(i)) => {
            state.tab = all()[i];
            if state.tab == Tab::Set {
                state.load_edit();
            }
            return EventOutcome::Repaint;
        }
        Some(Target::Key(k)) => k,
        None => return EventOutcome::Idle,
    };
    match state.tab {
        Tab::Stopwatch => stopwatch_key(state, key),
        Tab::Timer => timer_key(state, key),
        Tab::Set => settime_key(state, key),
        Tab::Clock => EventOutcome::Idle,
    }
}

fn settime_key(state: &mut State, key: usize) -> EventOutcome {
    if key == 0 {
        state.edit_hour = (state.edit_hour + 23) % 24;
    } else if key == 1 {
        state.edit_hour = (state.edit_hour + 1) % 24;
    } else if key == 2 {
        state.edit_min = (state.edit_min + 59) % 60;
    } else if key == 3 {
        state.edit_min = (state.edit_min + 1) % 60;
    } else if key == 4 {
        // The new time is set on today's date, which only the system clock
        // knows; with no reading there is no date to send.
        if !state.clock_ok {
            state.set_note = NO_DATE;
            return EventOutcome::Repaint;
        }
        let ms = civil::to_unix_ms(
            state.rtc.year,
            state.rtc.month,
            state.rtc.day,
            state.edit_hour,
            state.edit_min,
            0,
        );
        state.set_note = adjust_outcome(mk_time_adjust(ms));
        state.refresh();
        return EventOutcome::Repaint;
    } else {
        return EventOutcome::Idle;
    }
    state.set_note = b"";
    EventOutcome::Repaint
}

fn timer_key(state: &mut State, key: usize) -> EventOutcome {
    match key {
        0 => state.timer.set(60_000),
        1 => state.timer.set(300_000),
        2 => state.timer.set(600_000),
        3 => state.timer.toggle(state.now_ms),
        4 => state.timer.reset(),
        _ => return EventOutcome::Idle,
    }
    EventOutcome::Repaint
}

fn stopwatch_key(state: &mut State, key: usize) -> EventOutcome {
    match key {
        0 => state.sw.toggle(state.now_ms),
        1 => state.sw.reset(),
        _ => return EventOutcome::Idle,
    }
    EventOutcome::Repaint
}
