// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::*;
use super::utils::{draw_number, draw_rounded_rect, draw_status_pill, draw_string};
use crate::graphics::framebuffer::{
    fill_rect, COLOR_GREEN, COLOR_RED, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::process::core::types::{Priority, ProcessState};
use crate::process::types::Process;

pub(super) fn draw_row(x: u32, y: u32, w: u32, i: usize, proc: &Process) -> (bool, u64) {
    let py = y + (i as u32) * ROW_HEIGHT;
    if i % 2 == 1 {
        fill_rect(x, py, w, ROW_HEIGHT - 2, COLOR_ROW_ALT);
    }
    draw_number(x + 16, py + 10, proc.pid, COLOR_TEXT_WHITE);
    let name = proc.name.as_bytes();
    draw_string(x + 60, py + 10, &name[..name.len().min(16)], COLOR_TEXT_WHITE);
    let (running, mem) = draw_state_and_priority(x, py, w, proc);
    (running, mem)
}

fn draw_state_and_priority(x: u32, py: u32, w: u32, proc: &Process) -> (bool, u64) {
    let (txt, bg, fg, run): (&[u8], u32, u32, bool) = match proc.state() {
        ProcessState::New => (b"new", 0xFF2A2A32, COLOR_TEXT_DIM, false),
        ProcessState::Ready => (b"ready", 0xFF332D00, COLOR_YELLOW, false),
        ProcessState::Running => (b"run", 0xFF103520, COLOR_GREEN, true),
        ProcessState::Sleeping => (b"sleep", 0xFF222230, 0xFF8B8BAF, false),
        ProcessState::Stopped => (b"stop", 0xFF351818, COLOR_RED, false),
        ProcessState::Zombie(_) => (b"zombie", 0xFF351818, COLOR_RED, false),
        ProcessState::Terminated(_) => (b"exit", 0xFF2A2A32, COLOR_TEXT_DIM, false),
    };
    draw_status_pill(x + 200, py + 7, txt, bg, fg);
    let mem = draw_priority_and_mem(x, py, w, proc);
    (run, mem)
}

fn draw_priority_and_mem(x: u32, py: u32, w: u32, proc: &Process) -> u64 {
    if let Some(prio) = proc.priority() {
        let ps: &[u8] = match prio {
            Priority::Idle => b"idle",
            Priority::Low => b"low",
            Priority::Normal => b"norm",
            Priority::High => b"high",
            Priority::RealTime => b"rt",
        };
        draw_string(x + 290, py + 10, ps, COLOR_TEXT_DIM);
        let mem = proc.resident_memory_kb();
        let mw = draw_number(x + 370, py + 10, mem as u32, COLOR_TEXT_DIM);
        draw_string(x + 370 + mw, py + 10, b" KB", COLOR_TEXT_DIM);
        draw_kill_btn(x, py, w, proc);
        mem
    } else {
        draw_string(x + 290, py + 10, b"--", COLOR_TEXT_DIM);
        draw_string(x + 370, py + 10, b"-- KB", COLOR_TEXT_DIM);
        0
    }
}

fn draw_kill_btn(x: u32, py: u32, w: u32, proc: &Process) {
    let can = proc.pid > 1 && !matches!(proc.name.as_str(), "kernel" | "init");
    if can {
        draw_rounded_rect(x + w - 70, py + 6, 55, 22, 4, 0xFF4A1818);
        draw_string(x + w - 58, py + 10, b"Kill", COLOR_RED);
    }
}
