// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const KBD_DATA: u16 = 0x60;
pub const KBD_STATUS: u16 = 0x64;
pub const KBD_CMD: u16 = 0x64;
pub const CMD_READ_CFG: u8 = 0x20;
pub const CMD_WRITE_CFG: u8 = 0x60;
pub const CMD_DISABLE_PORT1: u8 = 0xAD;
pub const CMD_ENABLE_PORT1: u8 = 0xAE;
pub const CMD_SELF_TEST: u8 = 0xAA;
pub const KBD_ENABLE_SCANNING: u8 = 0xF4;
pub const KBD_DISABLE_SCANNING: u8 = 0xF5;
pub const KBD_SET_LEDS: u8 = 0xED;
pub const KBD_RESET: u8 = 0xFF;
pub const KBD_ACK: u8 = 0xFA;
pub const KBD_RESEND: u8 = 0xFE;
pub const STATUS_OUTPUT_FULL: u8 = 0x01;
pub const STATUS_INPUT_FULL: u8 = 0x02;
pub const STATUS_SYSTEM_FLAG: u8 = 0x04;
pub const STATUS_CMD_DATA: u8 = 0x08;
pub const STATUS_KEYBOARD_LOCK: u8 = 0x10;
pub const STATUS_TIMEOUT: u8 = 0x40;
pub const STATUS_PARITY: u8 = 0x80;
pub const KBD_VECTOR: u8 = 0x21;
pub const SC_EXT_E0: u8 = 0xE0;
pub const SC_EXT_E1: u8 = 0xE1;
pub const SC_BREAK_BIT: u8 = 0x80;
pub const NORMAL: [Option<u8>; 0x60] = {
    let mut t: [Option<u8>; 0x60] = [None; 0x60];
    t[0x02] = Some(b'1');
    t[0x03] = Some(b'2');
    t[0x04] = Some(b'3');
    t[0x05] = Some(b'4');
    t[0x06] = Some(b'5');
    t[0x07] = Some(b'6');
    t[0x08] = Some(b'7');
    t[0x09] = Some(b'8');
    t[0x0A] = Some(b'9');
    t[0x0B] = Some(b'0');
    t[0x0C] = Some(b'-');
    t[0x0D] = Some(b'=');
    t[0x0E] = Some(0x08);
    t[0x0F] = Some(b'\t');
    t[0x10] = Some(b'q');
    t[0x11] = Some(b'w');
    t[0x12] = Some(b'e');
    t[0x13] = Some(b'r');
    t[0x14] = Some(b't');
    t[0x15] = Some(b'y');
    t[0x16] = Some(b'u');
    t[0x17] = Some(b'i');
    t[0x18] = Some(b'o');
    t[0x19] = Some(b'p');
    t[0x1A] = Some(b'[');
    t[0x1B] = Some(b']');
    t[0x1C] = Some(b'\n');
    t[0x1E] = Some(b'a');
    t[0x1F] = Some(b's');
    t[0x20] = Some(b'd');
    t[0x21] = Some(b'f');
    t[0x22] = Some(b'g');
    t[0x23] = Some(b'h');
    t[0x24] = Some(b'j');
    t[0x25] = Some(b'k');
    t[0x26] = Some(b'l');
    t[0x27] = Some(b';');
    t[0x28] = Some(b'\'');
    t[0x29] = Some(b'`');
    t[0x2B] = Some(b'\\');
    t[0x2C] = Some(b'z');
    t[0x2D] = Some(b'x');
    t[0x2E] = Some(b'c');
    t[0x2F] = Some(b'v');
    t[0x30] = Some(b'b');
    t[0x31] = Some(b'n');
    t[0x32] = Some(b'm');
    t[0x33] = Some(b',');
    t[0x34] = Some(b'.');
    t[0x35] = Some(b'/');
    t[0x39] = Some(b' ');
    t
};

pub const SHIFTED: [Option<u8>; 0x60] = {
    let mut t: [Option<u8>; 0x60] = [None; 0x60];
    t[0x02] = Some(b'!');
    t[0x03] = Some(b'@');
    t[0x04] = Some(b'#');
    t[0x05] = Some(b'$');
    t[0x06] = Some(b'%');
    t[0x07] = Some(b'^');
    t[0x08] = Some(b'&');
    t[0x09] = Some(b'*');
    t[0x0A] = Some(b'(');
    t[0x0B] = Some(b')');
    t[0x0C] = Some(b'_');
    t[0x0D] = Some(b'+');
    t[0x0E] = Some(0x08);
    t[0x0F] = Some(b'\t');
    t[0x10] = Some(b'Q');
    t[0x11] = Some(b'W');
    t[0x12] = Some(b'E');
    t[0x13] = Some(b'R');
    t[0x14] = Some(b'T');
    t[0x15] = Some(b'Y');
    t[0x16] = Some(b'U');
    t[0x17] = Some(b'I');
    t[0x18] = Some(b'O');
    t[0x19] = Some(b'P');
    t[0x1A] = Some(b'{');
    t[0x1B] = Some(b'}');
    t[0x1C] = Some(b'\n');
    t[0x1E] = Some(b'A');
    t[0x1F] = Some(b'S');
    t[0x20] = Some(b'D');
    t[0x21] = Some(b'F');
    t[0x22] = Some(b'G');
    t[0x23] = Some(b'H');
    t[0x24] = Some(b'J');
    t[0x25] = Some(b'K');
    t[0x26] = Some(b'L');
    t[0x27] = Some(b':');
    t[0x28] = Some(b'"');
    t[0x29] = Some(b'~');
    t[0x2B] = Some(b'|');
    t[0x2C] = Some(b'Z');
    t[0x2D] = Some(b'X');
    t[0x2E] = Some(b'C');
    t[0x2F] = Some(b'V');
    t[0x30] = Some(b'B');
    t[0x31] = Some(b'N');
    t[0x32] = Some(b'M');
    t[0x33] = Some(b'<');
    t[0x34] = Some(b'>');
    t[0x35] = Some(b'?');
    t[0x39] = Some(b' ');
    t
};

pub const SC_LSHIFT: u8 = 0x2A;
pub const SC_RSHIFT: u8 = 0x36;
pub const SC_LCTRL: u8 = 0x1D;
pub const SC_LALT: u8 = 0x38;
pub const SC_CAPSLOCK: u8 = 0x3A;
pub const SC_NUMLOCK: u8 = 0x45;
pub const SC_SCROLLLOCK: u8 = 0x46;
pub const SC_EXT_UP: u8 = 0x48;
pub const SC_EXT_DOWN: u8 = 0x50;
pub const SC_EXT_LEFT: u8 = 0x4B;
pub const SC_EXT_RIGHT: u8 = 0x4D;
pub const SC_EXT_HOME: u8 = 0x47;
pub const SC_EXT_END: u8 = 0x4F;
pub const SC_EXT_PGUP: u8 = 0x49;
pub const SC_EXT_PGDN: u8 = 0x51;
pub const SC_EXT_INSERT: u8 = 0x52;
pub const SC_EXT_DELETE: u8 = 0x53;
pub const LED_SCROLL_LOCK: u8 = 0b001;
pub const LED_NUM_LOCK: u8 = 0b010;
pub const LED_CAPS_LOCK: u8 = 0b100;
pub const CHAR_RING_SIZE: usize = 1024;
pub const EVT_RING_SIZE: usize = 64;
pub const KBD_MAX_INTERRUPTS_PER_SEC: u64 = 1000; /// Maximum keyboard interrupts per second (protects against malfunctioning hardware).
pub const KBD_RATE_LIMIT_WINDOW_US: u64 = 1_000_000;
