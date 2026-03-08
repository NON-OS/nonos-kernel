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

use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN, COLOR_RED, COLOR_YELLOW};
use crate::graphics::font::draw_char;
use crate::process::get_all_processes;
use crate::process::core::types::ProcessState;
use crate::graphics::window::state::TITLE_BAR_HEIGHT;

const COLOR_BG: u32 = 0xFF000000;
const COLOR_HEADER: u32 = 0xFF2C2C2E;
const COLOR_ROW_ALT: u32 = 0xFF1C1C1E;
const COLOR_TEXT_DIM: u32 = 0xFF8E8E93;
const COLOR_BORDER: u32 = 0xFF38383A;

fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for dy in 0..r {
        for dx in 0..r {
            if dx * dx + dy * dy <= r * r {
                put_pixel(x + r - dx, y + r - dy, color);
                put_pixel(x + w - r + dx - 1, y + r - dy, color);
                put_pixel(x + r - dx, y + h - r + dy - 1, color);
                put_pixel(x + w - r + dx - 1, y + h - r + dy - 1, color);
            }
        }
    }
}

fn draw_status_pill(x: u32, y: u32, text: &[u8], bg_color: u32, text_color: u32) {
    draw_rounded_rect(x, y, 60, 18, 4, bg_color);
    draw_string(x + 6, y + 3, text, text_color);
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
    fill_rect(x, y, w, h, COLOR_BG);

    for gy in 0..44u32 {
        let shade = 44 - (gy / 3) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + gy, w, 1, color);
    }
    fill_rect(x, y + 43, w, 1, COLOR_BORDER);

    draw_string(x + 16, y + 14, b"System Processes", COLOR_ACCENT);

    draw_rounded_rect(x + w - 90, y + 8, 76, 28, 6, 0xFF3A3A3C);
    draw_string(x + w - 76, y + 14, b"Refresh", COLOR_TEXT_WHITE);

    fill_rect(x, y + 44, w, 28, COLOR_HEADER);
    fill_rect(x, y + 71, w, 1, COLOR_BORDER);
    draw_string(x + 16, y + 52, b"PID", COLOR_TEXT_DIM);
    draw_string(x + 60, y + 52, b"Name", COLOR_TEXT_DIM);
    draw_string(x + 200, y + 52, b"Status", COLOR_TEXT_DIM);
    draw_string(x + 290, y + 52, b"Priority", COLOR_TEXT_DIM);
    draw_string(x + 370, y + 52, b"Memory", COLOR_TEXT_DIM);
    draw_string(x + w - 70, y + 52, b"Action", COLOR_TEXT_DIM);

    let processes = get_all_processes();
    let max_display = ((h - 110) / 36) as usize;
    let mut total_memory: u64 = 0;
    let mut running_count = 0u32;

    for (i, proc) in processes.iter().take(max_display).enumerate() {
        let py = y + 76 + (i as u32) * 36;

        if i % 2 == 1 {
            fill_rect(x, py, w, 34, COLOR_ROW_ALT);
        }

        draw_number(x + 16, py + 10, proc.pid, COLOR_TEXT_WHITE);

        let name_bytes = proc.name.as_bytes();
        let name_len = name_bytes.len().min(16);
        draw_string(x + 60, py + 10, &name_bytes[..name_len], COLOR_TEXT_WHITE);

        let (state_str, state_bg, state_text, is_running): (&[u8], u32, u32, bool) = match proc.state() {
            ProcessState::New => (b"new", 0xFF3A3A3C, COLOR_TEXT_DIM, false),
            ProcessState::Ready => (b"ready", 0xFF3A3500, COLOR_YELLOW, false),
            ProcessState::Running => (b"run", 0xFF1A3A1A, COLOR_GREEN, true),
            ProcessState::Sleeping => (b"sleep", 0xFF2A2A3C, 0xFF8E8EAA, false),
            ProcessState::Stopped => (b"stop", 0xFF3A1A1A, COLOR_RED, false),
            ProcessState::Zombie(_) => (b"zombie", 0xFF3A1A1A, COLOR_RED, false),
            ProcessState::Terminated(_) => (b"exit", 0xFF2C2C2E, COLOR_TEXT_DIM, false),
        };

        draw_status_pill(x + 200, py + 7, state_str, state_bg, state_text);
        if is_running {
            running_count += 1;
        }

        if let Some(priority) = proc.priority() {
            use crate::process::core::types::Priority;
            let prio_str: &[u8] = match priority {
                Priority::Idle => b"idle",
                Priority::Low => b"low",
                Priority::Normal => b"norm",
                Priority::High => b"high",
                Priority::RealTime | Priority::Realtime => b"rt",
            };
            draw_string(x + 290, py + 10, prio_str, COLOR_TEXT_DIM);

            let mem_kb = proc.resident_memory_kb();
            total_memory += mem_kb;

            let width = draw_number(x + 370, py + 10, mem_kb as u32, COLOR_TEXT_DIM);
            draw_string(x + 370 + width, py + 10, b" KB", COLOR_TEXT_DIM);
        } else {
            draw_string(x + 290, py + 10, b"--", COLOR_TEXT_DIM);
            draw_string(x + 370, py + 10, b"-- KB", COLOR_TEXT_DIM);
        }

        let can_kill = proc.pid > 1 && !matches!(proc.name.as_str(), "kernel" | "init");
        if can_kill {
            draw_rounded_rect(x + w - 70, py + 6, 55, 22, 4, 0xFF5A2020);
            draw_string(x + w - 58, py + 10, b"Kill", COLOR_RED);
        }
    }

    for gy in 0..32u32 {
        let shade = 28 - (gy / 4) as u8;
        let color = 0xFF000000 | ((shade as u32) << 16) | ((shade as u32) << 8) | (shade as u32);
        fill_rect(x, y + h - 32 + gy, w, 1, color);
    }
    fill_rect(x, y + h - 32, w, 1, COLOR_BORDER);

    let proc_count = processes.len() as u32;
    let width1 = draw_number(x + 16, y + h - 22, proc_count, COLOR_TEXT_DIM);
    draw_string(x + 16 + width1, y + h - 22, b" processes", COLOR_TEXT_DIM);

    fill_rect(x + 16 + width1 + 88, y + h - 26, 1, 12, COLOR_BORDER);

    let offset2 = x + 16 + width1 + 96;
    let width2 = draw_number(offset2, y + h - 22, running_count, COLOR_GREEN);
    draw_string(offset2 + width2, y + h - 22, b" running", COLOR_TEXT_DIM);

    fill_rect(offset2 + width2 + 72, y + h - 26, 1, 12, COLOR_BORDER);

    let offset3 = offset2 + width2 + 80;
    let width3 = draw_number(offset3, y + h - 22, total_memory as u32, COLOR_ACCENT);
    draw_string(offset3 + width3, y + h - 22, b" KB", COLOR_TEXT_DIM);
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
