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

use core::ptr::addr_of_mut;

use super::input::get_editor;
use super::renderer::{draw_text_at, clear_row, COLOR_TEXT_DIM, MAX_ROWS};

pub const MAX_COMPLETIONS: usize = 16;
pub const MAX_COMPLETION_LEN: usize = 32;

static COMMANDS: &[&[u8]] = &[
    b"about", b"alias", b"anon", b"apps", b"arp", b"audit",
    b"browser",
    b"calc", b"caps", b"capsules", b"cat", b"cd", b"chmod", b"chown", b"clear",
    b"cp", b"cpu", b"crypto", b"curl",
    b"date", b"depmod", b"df", b"dmesg", b"dns", b"du",
    b"echo", b"editor", b"env", b"exit", b"export",
    b"file", b"files", b"find", b"firewall", b"free",
    b"genkey", b"grep",
    b"hash", b"head", b"help", b"history", b"hmac", b"hostname",
    b"id", b"ifconfig", b"info", b"insmod", b"integrity", b"ip",
    b"jobs",
    b"kill", b"kver",
    b"ln", b"locks", b"logo", b"ls", b"lsblk", b"lscpu", b"lsmod", b"lspci", b"lsusb",
    b"mem", b"mkdir", b"modinfo", b"monitor", b"mv",
    b"neofetch", b"net", b"netstat", b"nice", b"nslookup",
    b"pgrep", b"pidof", b"ping", b"pkill", b"poweroff", b"ps", b"pwd",
    b"random", b"reboot", b"renice", b"rm", b"rmdir", b"rmmod", b"rootkit-scan", b"route",
    b"secstatus", b"sessions", b"settings", b"shutdown", b"sleep", b"source", b"ss",
    b"stat", b"suspend", b"sysctl", b"sysmon",
    b"tail", b"time", b"top", b"tor", b"touch", b"traceroute", b"true", b"type",
    b"uname", b"unset", b"uptime",
    b"vault", b"vault-audit", b"vault-decrypt", b"vault-derive", b"vault-encrypt",
    b"vault-erase", b"vault-keys", b"vault-policy", b"vault-seal", b"vault-sign",
    b"vault-unseal", b"vault-verify", b"version",
    b"wc", b"wget", b"which", b"whoami",
];

pub struct Completer {
    matches: [[u8; MAX_COMPLETION_LEN]; MAX_COMPLETIONS],
    match_lens: [usize; MAX_COMPLETIONS],
    match_count: usize,
    current_match: usize,
    prefix_len: usize,
    showing: bool,
}

impl Completer {
    pub const fn new() -> Self {
        Self {
            matches: [[0u8; MAX_COMPLETION_LEN]; MAX_COMPLETIONS],
            match_lens: [0; MAX_COMPLETIONS],
            match_count: 0,
            current_match: 0,
            prefix_len: 0,
            showing: false,
        }
    }

    pub fn find_completions(&mut self, prefix: &[u8]) {
        self.match_count = 0;
        self.current_match = 0;
        self.prefix_len = prefix.len();

        if prefix.is_empty() {
            return;
        }

        for &cmd in COMMANDS {
            if self.match_count >= MAX_COMPLETIONS {
                break;
            }

            if cmd.len() >= prefix.len() && &cmd[..prefix.len()] == prefix {
                let len = cmd.len().min(MAX_COMPLETION_LEN);
                self.matches[self.match_count][..len].copy_from_slice(&cmd[..len]);
                self.match_lens[self.match_count] = len;
                self.match_count += 1;
            }
        }
    }

    pub fn complete(&mut self, input: &[u8]) -> Option<&[u8]> {
        let word_start = input.iter().rposition(|&c| c == b' ').map_or(0, |p| p + 1);
        let prefix = &input[word_start..];

        if !self.showing || self.prefix_len != prefix.len() {
            self.find_completions(prefix);
            self.showing = true;
        }

        if self.match_count == 0 {
            return None;
        }

        if self.match_count == 1 {
            self.showing = false;
            let len = self.match_lens[0];
            return Some(&self.matches[0][..len]);
        }

        let len = self.match_lens[self.current_match];
        self.current_match = (self.current_match + 1) % self.match_count;
        Some(&self.matches[self.current_match.wrapping_sub(1) % self.match_count][..len])
    }

    pub fn show_all(&self, row: u32) {
        if self.match_count <= 1 {
            return;
        }

        let display_row = if row + 2 < MAX_ROWS { row + 1 } else { row - 1 };
        clear_row(display_row);

        let mut col = 0u32;
        for i in 0..self.match_count.min(6) {
            let len = self.match_lens[i];
            draw_text_at(col, display_row, &self.matches[i][..len], COLOR_TEXT_DIM);
            col += len as u32 + 2;
        }

        if self.match_count > 6 {
            draw_text_at(col, display_row, b"...", COLOR_TEXT_DIM);
        }
    }

    pub fn reset(&mut self) {
        self.match_count = 0;
        self.current_match = 0;
        self.prefix_len = 0;
        self.showing = false;
    }

    pub fn is_showing(&self) -> bool {
        self.showing
    }

    pub fn match_count(&self) -> usize {
        self.match_count
    }
}

static mut COMPLETER: Completer = Completer::new();

pub fn get_completer() -> &'static mut Completer {
    // SAFETY: Completer is only accessed from the main thread during terminal
    // operations. No concurrent access occurs as the shell is single-threaded.
    // Using addr_of_mut! to avoid creating a mutable reference to the static directly.
    unsafe { &mut *addr_of_mut!(COMPLETER) }
}

pub fn complete() {
    let editor = get_editor();
    let input = editor.get_content();
    let input_len = input.len();
    let word_start = input.iter().rposition(|&c| c == b' ').map_or(0, |p| p + 1);

    let completer = get_completer();

    // Copy completion data to break the borrow chain
    let mut completion_buf = [0u8; MAX_COMPLETION_LEN];
    let completion_len;

    if let Some(completion) = completer.complete(input) {
        completion_len = completion.len().min(MAX_COMPLETION_LEN);
        completion_buf[..completion_len].copy_from_slice(&completion[..completion_len]);
    } else {
        return;
    }

    let match_count = completer.match_count();
    let delete_count = input_len - word_start;

    // Now safe to mutate editor
    editor.move_end();

    for _ in 0..delete_count {
        editor.backspace();
    }

    for &ch in &completion_buf[..completion_len] {
        editor.insert_char(ch);
    }

    editor.insert_char(b' ');

    if match_count > 1 {
        completer.show_all(editor.row());
    }
}

pub fn reset() {
    get_completer().reset();
}
