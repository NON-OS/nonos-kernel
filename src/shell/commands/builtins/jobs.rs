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

use core::ptr::{addr_of, addr_of_mut};
use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};

const MAX_JOBS: usize = 8;
const MAX_JOB_CMD_LEN: usize = 64;

#[derive(Clone, Copy)]
struct Job {
    id: u32,
    cmd: [u8; MAX_JOB_CMD_LEN],
    cmd_len: usize,
    running: bool,
}

impl Job {
    const fn empty() -> Self {
        Self {
            id: 0,
            cmd: [0u8; MAX_JOB_CMD_LEN],
            cmd_len: 0,
            running: false,
        }
    }
}

static mut JOBS: [Job; MAX_JOBS] = [Job::empty(); MAX_JOBS];
static mut NEXT_JOB_ID: u32 = 1;
static mut CURRENT_JOB: Option<usize> = None;

pub fn cmd_wait() {
    // SAFETY: Single-threaded shell context
    let jobs = unsafe { &*addr_of!(JOBS) };

    let mut has_jobs = false;
    for i in 0..MAX_JOBS {
        if jobs[i].running {
            has_jobs = true;
            break;
        }
    }

    if !has_jobs {
        print_line(b"wait: No background jobs", COLOR_TEXT_DIM);
        return;
    }

    print_line(b"wait: All jobs completed (synchronous execution)", COLOR_GREEN);

    // SAFETY: Single-threaded shell context
    unsafe {
        for i in 0..MAX_JOBS {
            (*addr_of_mut!(JOBS))[i].running = false;
        }
    }
}

pub fn cmd_bg() {
    // SAFETY: Single-threaded shell context
    let (jobs, current) = unsafe { (&mut *addr_of_mut!(JOBS), *addr_of!(CURRENT_JOB)) };

    if let Some(idx) = current {
        if idx < MAX_JOBS && jobs[idx].running {
            let mut msg = [0u8; 80];
            msg[..5].copy_from_slice(b"[bg] ");
            let cmd_len = jobs[idx].cmd_len.min(60);
            msg[5..5+cmd_len].copy_from_slice(&jobs[idx].cmd[..cmd_len]);
            print_line(&msg[..5+cmd_len], COLOR_GREEN);
            print_line(b"(Job continues in background - sync mode)", COLOR_TEXT_DIM);
            return;
        }
    }

    for i in 0..MAX_JOBS {
        if jobs[i].running {
            let mut msg = [0u8; 80];
            msg[..5].copy_from_slice(b"[bg] ");
            let cmd_len = jobs[i].cmd_len.min(60);
            msg[5..5+cmd_len].copy_from_slice(&jobs[i].cmd[..cmd_len]);
            print_line(&msg[..5+cmd_len], COLOR_GREEN);
            return;
        }
    }

    print_line(b"bg: No current job", COLOR_YELLOW);
}

pub fn cmd_fg() {
    // SAFETY: Single-threaded shell context
    let jobs = unsafe { &mut *addr_of_mut!(JOBS) };

    for i in 0..MAX_JOBS {
        if jobs[i].running {
            let mut msg = [0u8; 80];
            msg[..5].copy_from_slice(b"[fg] ");
            let cmd_len = jobs[i].cmd_len.min(60);
            msg[5..5+cmd_len].copy_from_slice(&jobs[i].cmd[..cmd_len]);
            print_line(&msg[..5+cmd_len], COLOR_GREEN);

            jobs[i].running = false;
            // SAFETY: Single-threaded shell context
            unsafe { *addr_of_mut!(CURRENT_JOB) = None; }
            return;
        }
    }

    print_line(b"fg: No background jobs", COLOR_YELLOW);
}

pub fn add_background_job(cmd: &[u8]) -> u32 {
    // SAFETY: Single-threaded shell context
    unsafe {
        let jobs = &mut *addr_of_mut!(JOBS);
        for i in 0..MAX_JOBS {
            if !jobs[i].running {
                jobs[i].id = *addr_of!(NEXT_JOB_ID);
                *addr_of_mut!(NEXT_JOB_ID) += 1;
                let len = cmd.len().min(MAX_JOB_CMD_LEN);
                jobs[i].cmd[..len].copy_from_slice(&cmd[..len]);
                jobs[i].cmd_len = len;
                jobs[i].running = true;
                *addr_of_mut!(CURRENT_JOB) = Some(i);

                let id = jobs[i].id;

                let mut msg = [0u8; 16];
                msg[0] = b'[';
                let id_str = format_u32(id);
                let id_len = id_str.1;
                msg[1..1+id_len].copy_from_slice(&id_str.0[..id_len]);
                msg[1+id_len] = b']';
                msg[2+id_len] = b' ';

                print_line(&msg[..3+id_len], COLOR_TEXT_DIM);
                return id;
            }
        }
    }
    print_line(b"bg: Too many background jobs", COLOR_YELLOW);
    0
}

pub fn complete_job(id: u32) {
    // SAFETY: Single-threaded shell context
    unsafe {
        let jobs = &mut *addr_of_mut!(JOBS);
        for i in 0..MAX_JOBS {
            if jobs[i].running && jobs[i].id == id {
                jobs[i].running = false;
                if *addr_of!(CURRENT_JOB) == Some(i) {
                    *addr_of_mut!(CURRENT_JOB) = None;
                }

                let mut msg = [0u8; 80];
                msg[..6].copy_from_slice(b"Done: ");
                let cmd_len = jobs[i].cmd_len.min(60);
                msg[6..6+cmd_len].copy_from_slice(&jobs[i].cmd[..cmd_len]);
                print_line(&msg[..6+cmd_len], COLOR_GREEN);
                return;
            }
        }
    }
}

pub fn list_jobs() {
    // SAFETY: Single-threaded shell context
    let jobs = unsafe { &*addr_of!(JOBS) };

    let mut has_jobs = false;
    for i in 0..MAX_JOBS {
        if jobs[i].running {
            has_jobs = true;
            let mut line = [0u8; 80];
            line[0] = b'[';
            let id_str = format_u32(jobs[i].id);
            let id_len = id_str.1;
            line[1..1+id_len].copy_from_slice(&id_str.0[..id_len]);
            line[1+id_len] = b']';
            line[2+id_len] = b' ';
            line[3+id_len..3+id_len+7].copy_from_slice(b"Running");
            line[10+id_len] = b' ';

            let cmd_len = jobs[i].cmd_len.min(50);
            line[11+id_len..11+id_len+cmd_len].copy_from_slice(&jobs[i].cmd[..cmd_len]);

            print_line(&line[..11+id_len+cmd_len], COLOR_GREEN);
        }
    }

    if !has_jobs {
        print_line(b"No background jobs", COLOR_TEXT_DIM);
    }
}

fn format_u32(n: u32) -> ([u8; 10], usize) {
    let mut buf = [0u8; 10];
    if n == 0 {
        buf[0] = b'0';
        return (buf, 1);
    }
    let mut val = n;
    let mut pos = 10;
    while val > 0 && pos > 0 {
        pos -= 1;
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    let len = 10 - pos;
    let mut result = [0u8; 10];
    result[..len].copy_from_slice(&buf[pos..]);
    (result, len)
}
