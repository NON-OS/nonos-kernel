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
use super::builtins::env::get_env;

const MAX_EXPANDED_LEN: usize = 512;

pub fn expand_variables(input: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        if input[i] == b'$' && i + 1 < input.len() {
            if input[i + 1] == b'{' {
                if let Some((var_name, end_pos)) = parse_braced_var(&input[i + 2..]) {
                    if let Some(value) = get_env().get(var_name) {
                        result.extend_from_slice(value);
                    }
                    i = i + 2 + end_pos + 1;
                    continue;
                }
            } else if is_var_start_char(input[i + 1]) {
                let var_start = i + 1;
                let mut var_end = var_start;
                while var_end < input.len() && is_var_char(input[var_end]) {
                    var_end += 1;
                }

                let var_name = &input[var_start..var_end];
                if !var_name.is_empty() {
                    if let Some(value) = get_env().get(var_name) {
                        result.extend_from_slice(value);
                    }
                    i = var_end;
                    continue;
                }
            } else if input[i + 1] == b'?' {
                result.extend_from_slice(b"0");
                i += 2;
                continue;
            } else if input[i + 1] == b'$' {
                let pid = crate::process::current_pid().unwrap_or(1);
                let mut buf = [0u8; 16];
                let len = format_num(&mut buf, pid as usize);
                result.extend_from_slice(&buf[..len]);
                i += 2;
                continue;
            }
        }

        if result.len() < MAX_EXPANDED_LEN {
            result.push(input[i]);
        }
        i += 1;
    }

    result
}

fn parse_braced_var(input: &[u8]) -> Option<(&[u8], usize)> {
    let mut end = 0;
    while end < input.len() && input[end] != b'}' {
        end += 1;
    }

    if end < input.len() && end > 0 {
        Some((&input[..end], end))
    } else {
        None
    }
}

fn is_var_start_char(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_var_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn format_num(buf: &mut [u8], mut n: usize) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut digits = [0u8; 20];
    let mut len = 0;

    while n > 0 {
        digits[len] = (n % 10) as u8 + b'0';
        n /= 10;
        len += 1;
    }

    for i in 0..len {
        buf[i] = digits[len - 1 - i];
    }

    len
}
