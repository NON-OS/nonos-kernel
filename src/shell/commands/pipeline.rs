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

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};

const MAX_PIPELINE_STAGES: usize = 8;
const MAX_CAPTURE_SIZE: usize = 65536;

static CAPTURE_MODE: AtomicBool = AtomicBool::new(false);
static mut CAPTURE_BUFFER: Option<Vec<u8>> = None;
static mut STDIN_BUFFER: Option<Vec<u8>> = None;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RedirectType {
    None,
    Write,
    Append,
    Input,
}

#[derive(Debug)]
pub struct PipelineStage<'a> {
    pub command: &'a [u8],
    pub redirect_type: RedirectType,
    pub redirect_target: Option<&'a [u8]>,
}

pub struct Pipeline<'a> {
    pub stages: Vec<PipelineStage<'a>>,
}

impl<'a> Pipeline<'a> {
    pub fn parse(input: &'a [u8]) -> Self {
        let mut stages = Vec::new();
        let mut current_start = 0;
        let mut i = 0;

        while i < input.len() {
            if input[i] == b'|' && !is_escaped(input, i) {
                if current_start < i {
                    let cmd = trim(&input[current_start..i]);
                    if !cmd.is_empty() && stages.len() < MAX_PIPELINE_STAGES {
                        stages.push(PipelineStage {
                            command: cmd,
                            redirect_type: RedirectType::None,
                            redirect_target: None,
                        });
                    }
                }
                current_start = i + 1;
            }
            i += 1;
        }

        if current_start < input.len() {
            let remaining = trim(&input[current_start..]);
            if !remaining.is_empty() {
                let (cmd, redir_type, redir_target) = parse_redirections(remaining);
                stages.push(PipelineStage {
                    command: cmd,
                    redirect_type: redir_type,
                    redirect_target: redir_target,
                });
            }
        }

        Pipeline { stages }
    }

    pub fn is_simple(&self) -> bool {
        self.stages.len() == 1 &&
        self.stages[0].redirect_type == RedirectType::None
    }

    pub fn has_pipes(&self) -> bool {
        self.stages.len() > 1
    }
}

fn parse_redirections(input: &[u8]) -> (&[u8], RedirectType, Option<&[u8]>) {
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'>' && !is_escaped(input, i) {
            let is_append = i + 1 < input.len() && input[i + 1] == b'>';
            let cmd = trim(&input[..i]);
            let target_start = if is_append { i + 2 } else { i + 1 };
            let target = trim(&input[target_start..]);
            let redir_type = if is_append { RedirectType::Append } else { RedirectType::Write };
            return (cmd, redir_type, if target.is_empty() { None } else { Some(target) });
        }
        if input[i] == b'<' && !is_escaped(input, i) {
            let cmd = trim(&input[..i]);
            let target = trim(&input[i + 1..]);
            return (cmd, RedirectType::Input, if target.is_empty() { None } else { Some(target) });
        }
        i += 1;
    }
    (input, RedirectType::None, None)
}

fn is_escaped(input: &[u8], pos: usize) -> bool {
    if pos == 0 {
        return false;
    }
    let mut backslashes = 0;
    let mut i = pos - 1;
    while i > 0 && input[i] == b'\\' {
        backslashes += 1;
        i -= 1;
    }
    if input[i] == b'\\' {
        backslashes += 1;
    }
    backslashes % 2 == 1
}

fn trim(input: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = input.len();

    while start < end && (input[start] == b' ' || input[start] == b'\t') {
        start += 1;
    }
    while end > start && (input[end - 1] == b' ' || input[end - 1] == b'\t') {
        end -= 1;
    }

    &input[start..end]
}

pub fn start_capture() {
    // SAFETY: Only called from single-threaded shell context
    unsafe {
        *addr_of_mut!(CAPTURE_BUFFER) = Some(Vec::with_capacity(MAX_CAPTURE_SIZE));
    }
    CAPTURE_MODE.store(true, Ordering::SeqCst);
}

pub fn stop_capture() -> Vec<u8> {
    CAPTURE_MODE.store(false, Ordering::SeqCst);
    // SAFETY: Only called from single-threaded shell context
    unsafe {
        (*addr_of_mut!(CAPTURE_BUFFER)).take().unwrap_or_default()
    }
}

pub fn is_capturing() -> bool {
    CAPTURE_MODE.load(Ordering::SeqCst)
}

pub fn capture_output(text: &[u8]) {
    if !is_capturing() {
        return;
    }
    // SAFETY: Only called from single-threaded shell context when capture is active
    unsafe {
        if let Some(ref mut buf) = *addr_of_mut!(CAPTURE_BUFFER) {
            if buf.len() + text.len() + 1 < MAX_CAPTURE_SIZE {
                buf.extend_from_slice(text);
                buf.push(b'\n');
            }
        }
    }
}

pub fn set_stdin(data: Vec<u8>) {
    // SAFETY: Only called from single-threaded shell context
    unsafe {
        *addr_of_mut!(STDIN_BUFFER) = Some(data);
    }
}

pub fn take_stdin() -> Option<Vec<u8>> {
    // SAFETY: Only called from single-threaded shell context
    unsafe {
        (*addr_of_mut!(STDIN_BUFFER)).take()
    }
}

pub fn has_stdin() -> bool {
    // SAFETY: Only called from single-threaded shell context
    unsafe {
        (*addr_of!(STDIN_BUFFER)).is_some()
    }
}

pub fn get_stdin_lines() -> Vec<Vec<u8>> {
    let data = take_stdin().unwrap_or_default();
    data.split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.to_vec())
        .collect()
}
