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

use crate::agents::{core::AgentConfig, presets, registry};
use crate::display::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_WHITE};
use crate::shell::output::print_line;

pub(super) fn list_agents() {
    let agents = registry::list_agents();
    if agents.is_empty() {
        print_line(b"No agents. Use 'agent create' or 'agent preset'", COLOR_WHITE);
        return;
    }
    for (id, name) in agents {
        let len = name.iter().position(|&c| c == 0).unwrap_or(32);
        let mut buf = [0u8; 64];
        let n = fmt_agent_line(id, &name[..len], &mut buf);
        print_line(&buf[..n], COLOR_WHITE);
    }
}

fn fmt_agent_line(id: u32, name: &[u8], buf: &mut [u8; 64]) -> usize {
    let mut i = fmt_u32(id, buf);
    buf[i] = b' ';
    i += 1;
    buf[i..i + name.len()].copy_from_slice(name);
    i + name.len()
}

fn fmt_u32(mut n: u32, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut i = 0;
    let mut tmp = [0u8; 10];
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

pub(super) fn create_agent(name: &str) {
    let mut cfg = AgentConfig::default();
    let len = name.len().min(32);
    cfg.name[..len].copy_from_slice(name.as_bytes());
    let id = registry::create_agent(cfg);
    let mut buf = [0u8; 32];
    let i = fmt_u32(id, &mut buf);
    print_line(b"Created agent", COLOR_GREEN);
    print_line(&buf[..i], COLOR_WHITE);
}

pub(super) fn list_presets() {
    print_line(b"Available presets:", COLOR_WHITE);
    for (name, _) in presets::list_presets() {
        print_line(name, COLOR_WHITE);
    }
}

pub(super) fn create_preset(name: &str) {
    for (pname, factory) in presets::list_presets() {
        if ci_contains(pname, name.as_bytes()) {
            let id = registry::create_agent(factory());
            let mut buf = [0u8; 32];
            let i = fmt_u32(id, &mut buf);
            print_line(b"Created agent from preset", COLOR_GREEN);
            print_line(&buf[..i], COLOR_WHITE);
            return;
        }
    }
    print_line(b"Preset not found", COLOR_RED);
}

fn ci_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return needle.is_empty();
    }
    'o: for i in 0..=hay.len() - needle.len() {
        for j in 0..needle.len() {
            let (a, b) = (hay[i + j].to_ascii_lowercase(), needle[j].to_ascii_lowercase());
            if a != b {
                continue 'o;
            }
        }
        return true;
    }
    false
}

pub(super) fn run_agent(id_str: &str, prompt: &str) {
    let id: u32 = id_str.parse().unwrap_or(0);
    if crate::agents::executor::run_agent(id, prompt.as_bytes()) {
        print_line(b"Agent running", COLOR_GREEN);
    } else {
        print_line(b"Failed to run agent", COLOR_RED);
    }
}

pub(super) fn delete_agent(id_str: &str) {
    if registry::delete_agent(id_str.parse().unwrap_or(0)) {
        print_line(b"Agent deleted", COLOR_GREEN);
    } else {
        print_line(b"Agent not found", COLOR_RED);
    }
}
