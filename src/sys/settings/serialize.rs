// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use super::types::Settings;

pub fn serialize(settings: &Settings, buf: &mut [u8]) -> usize {
    let mut pos = 0;

    write_u8(buf, &mut pos, b"brightness", settings.brightness);
    write_u8(buf, &mut pos, b"mouse_sens", settings.mouse_sensitivity);
    write_bool(buf, &mut pos, b"sound", settings.sound_enabled);
    write_bool(buf, &mut pos, b"anon_mode", settings.anonymous_mode);
    write_bool(buf, &mut pos, b"tor", settings.anyone_enabled);
    write_u8(buf, &mut pos, b"theme", settings.theme);
    write_u8(buf, &mut pos, b"kb_layout", settings.keyboard_layout);
    write_bool(buf, &mut pos, b"auto_wipe", settings.auto_wipe);

    pos
}

pub fn deserialize(buf: &[u8], settings: &mut Settings) {
    let mut line_start = 0;

    while line_start < buf.len() {
        let mut line_end = line_start;
        while line_end < buf.len() && buf[line_end] != b'\n' && buf[line_end] != 0 {
            line_end += 1;
        }

        if line_end > line_start {
            parse_line(&buf[line_start..line_end], settings);
        }

        line_start = line_end + 1;
    }
}

fn write_line(buf: &mut [u8], pos: &mut usize, key: &[u8], val: &[u8]) {
    for &ch in key {
        if *pos < buf.len() {
            buf[*pos] = ch;
            *pos += 1;
        }
    }
    if *pos < buf.len() {
        buf[*pos] = b'=';
        *pos += 1;
    }
    for &ch in val {
        if *pos < buf.len() {
            buf[*pos] = ch;
            *pos += 1;
        }
    }
    if *pos < buf.len() {
        buf[*pos] = b'\n';
        *pos += 1;
    }
}

fn write_u8(buf: &mut [u8], pos: &mut usize, key: &[u8], val: u8) {
    let mut num_buf = [0u8; 4];
    let len = format_u8(&mut num_buf, val);
    write_line(buf, pos, key, &num_buf[..len]);
}

fn write_bool(buf: &mut [u8], pos: &mut usize, key: &[u8], val: bool) {
    write_line(buf, pos, key, if val { b"1" } else { b"0" });
}

fn parse_line(line: &[u8], settings: &mut Settings) {
    let eq_pos = match line.iter().position(|&ch| ch == b'=') {
        Some(p) => p,
        None => return,
    };

    let key = &line[..eq_pos];
    let val = &line[eq_pos + 1..];

    if key == b"brightness" {
        if let Some(v) = parse_u8(val) {
            settings.brightness = v.min(100);
        }
    } else if key == b"mouse_sens" {
        if let Some(v) = parse_u8(val) {
            settings.mouse_sensitivity = v.clamp(1, 10);
        }
    } else if key == b"sound" {
        settings.sound_enabled = parse_bool(val);
    } else if key == b"anon_mode" {
        settings.anonymous_mode = parse_bool(val);
    } else if key == b"tor" {
        settings.anyone_enabled = parse_bool(val);
    } else if key == b"theme" {
        if let Some(v) = parse_u8(val) {
            settings.theme = v;
        }
    } else if key == b"kb_layout" {
        if let Some(v) = parse_u8(val) {
            settings.keyboard_layout = v;
        }
    } else if key == b"auto_wipe" {
        settings.auto_wipe = parse_bool(val);
    }
}

fn parse_u8(s: &[u8]) -> Option<u8> {
    let mut result: u8 = 0;
    for &ch in s {
        if ch >= b'0' && ch <= b'9' {
            result = result.saturating_mul(10).saturating_add(ch - b'0');
        } else {
            break;
        }
    }
    if s.is_empty() || s[0] < b'0' || s[0] > b'9' {
        None
    } else {
        Some(result)
    }
}

fn parse_bool(s: &[u8]) -> bool {
    !s.is_empty() && (s[0] == b'1' || s[0] == b't' || s[0] == b'T' || s[0] == b'y' || s[0] == b'Y')
}

fn format_u8(buf: &mut [u8], mut val: u8) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut digits = [0u8; 4];
    let mut pos = 0;
    while val > 0 {
        digits[pos] = b'0' + (val % 10);
        val /= 10;
        pos += 1;
    }

    for i in 0..pos {
        buf[i] = digits[pos - 1 - i];
    }
    pos
}
