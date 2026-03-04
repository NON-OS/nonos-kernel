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

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW};
use crate::graphics::font::draw_char;
use crate::process::get_all_processes;
use crate::process::core::types::ProcessState;
use crate::graphics::window::state::TITLE_BAR_HEIGHT;

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

fn draw_number(x: u32, y: u32, num: u32, color: u32) -> u32 {
    let mut buf = [0u8; 10];
    let mut n = num;
    let mut i = 0;

    if n == 0 {
        draw_char(x, y, b'0', color);
        return 8;
    }

    while n > 0 && i < 10 {
        buf[9 - i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    let start = 10 - i;
    for (j, &digit) in buf[start..].iter().enumerate() {
        draw_char(x + (j as u32) * 8, y, digit, color);
    }
    i as u32 * 8
}

pub(super) fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, 35, 0xFF21262D);
    draw_string(x + 15, y + 10, b"System Processes", COLOR_ACCENT);

    fill_rect(x + w - 80, y + 5, 70, 25, 0xFF2D333B);
    draw_string(x + w - 70, y + 10, b"Refresh", COLOR_TEXT_WHITE);

    fill_rect(x, y + 35, w, 25, 0xFF1C2128);
    draw_string(x + 15, y + 42, b"PID", 0xFF7D8590);
    draw_string(x + 60, y + 42, b"Name", 0xFF7D8590);
    draw_string(x + 200, y + 42, b"Status", 0xFF7D8590);
    draw_string(x + 290, y + 42, b"Priority", 0xFF7D8590);
    draw_string(x + 360, y + 42, b"Memory", 0xFF7D8590);
    draw_string(x + w - 70, y + 42, b"Action", 0xFF7D8590);

    let processes = get_all_processes();
    let max_display = ((h - 95) / 32) as usize;
    let mut total_memory: u64 = 0;
    let mut running_count = 0u32;

    for (i, proc) in processes.iter().take(max_display).enumerate() {
        let py = y + 65 + (i as u32) * 32;

        if i % 2 == 1 {
            fill_rect(x, py, w, 30, 0xFF1A1F26);
        }

        draw_number(x + 15, py + 8, proc.pid, COLOR_TEXT_WHITE);

        let name_bytes = proc.name.as_bytes();
        let name_len = name_bytes.len().min(16);
        draw_string(x + 60, py + 8, &name_bytes[..name_len], COLOR_TEXT_WHITE);

        let (state_str, state_color, is_running): (&[u8], u32, bool) = match proc.state() {
            ProcessState::New => (b"new     ", 0xFF7D8590, false),
            ProcessState::Ready => (b"ready   ", COLOR_YELLOW, false),
            ProcessState::Running => (b"running ", COLOR_GREEN, true),
            ProcessState::Sleeping => (b"sleeping", 0xFF7D8590, false),
            ProcessState::Stopped => (b"stopped ", COLOR_RED, false),
            ProcessState::Zombie(_) => (b"zombie  ", COLOR_RED, false),
            ProcessState::Terminated(_) => (b"exited  ", 0xFF7D8590, false),
        };

        draw_string(x + 200, py + 8, state_str, state_color);
        if is_running {
            running_count += 1;
        }

        if let Some(priority) = proc.priority() {
            use crate::process::core::types::Priority;
            let prio_str: &[u8] = match priority {
                Priority::Idle => b"idle  ",
                Priority::Low => b"low   ",
                Priority::Normal => b"normal",
                Priority::High => b"high  ",
                Priority::RealTime | Priority::Realtime => b"rt    ",
            };
            draw_string(x + 290, py + 8, prio_str, 0xFF7D8590);

            let mem_kb = proc.resident_memory_kb();
            total_memory += mem_kb;

            let width = draw_number(x + 360, py + 8, mem_kb as u32, 0xFF7D8590);
            draw_string(x + 360 + width, py + 8, b" KB", 0xFF7D8590);
        } else {
            draw_string(x + 290, py + 8, b"--    ", 0xFF7D8590);
            draw_string(x + 360, py + 8, b"-- KB", 0xFF7D8590);
        }

        let can_kill = proc.pid > 1 && !matches!(proc.name.as_str(), "kernel" | "init");
        if can_kill {
            fill_rect(x + w - 70, py + 5, 55, 20, 0xFF5A2020);
            draw_string(x + w - 60, py + 8, b"Kill", COLOR_RED);
        }
    }

    fill_rect(x, y + h - 30, w, 30, 0xFF161B22);

    let proc_count = processes.len() as u32;
    let width1 = draw_number(x + 15, y + h - 22, proc_count, 0xFF7D8590);
    draw_string(x + 15 + width1, y + h - 22, b" processes | ", 0xFF7D8590);

    let offset2 = x + 15 + width1 + 13 * 8;
    let width2 = draw_number(offset2, y + h - 22, running_count, 0xFF7D8590);
    draw_string(offset2 + width2, y + h - 22, b" running | ", 0xFF7D8590);

    let offset3 = offset2 + width2 + 11 * 8;
    let width3 = draw_number(offset3, y + h - 22, total_memory as u32, 0xFF7D8590);
    draw_string(offset3 + width3, y + h - 22, b" KB used", 0xFF7D8590);
}

pub(super) fn handle_click(win_x: u32, win_y: u32, win_w: u32, _win_h: u32, click_x: i32, click_y: i32) -> bool {
    let content_y = win_y + TITLE_BAR_HEIGHT;

    if click_x >= (win_x + win_w - 80) as i32
        && click_x < (win_x + win_w - 10) as i32
        && click_y >= content_y as i32 + 5
        && click_y <= content_y as i32 + 30 {
        return true;
    }

    if click_y >= content_y as i32 + 65 {
        let row = ((click_y - content_y as i32 - 65) / 32) as usize;
        let processes = get_all_processes();

        if row < processes.len() {
            let kill_btn_x = (win_x + win_w - 70) as i32;
            if click_x >= kill_btn_x && click_x < kill_btn_x + 55 {
                let proc = &processes[row];
                let can_kill = proc.pid > 1 && !matches!(proc.name.as_str(), "kernel" | "init");
                if can_kill {
                    proc.terminate_with_signal(9);
                    return true;
                }
            }
        }
    }

    false
}
