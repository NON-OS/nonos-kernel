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

use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_TEXT};
use crate::shell::output::print_line;
use crate::daemon::types::NodeTier;

pub(super) fn print_prefixed(prefix: &[u8], data: &[u8]) {
    let mut line = [0u8; 80];
    let plen = prefix.len().min(20);
    line[..plen].copy_from_slice(&prefix[..plen]);
    let dlen = data.len().min(60);
    line[plen..plen + dlen].copy_from_slice(&data[..dlen]);
    print_line(&line[..plen + dlen], COLOR_TEXT);
}

pub(super) fn print_tier(prefix: &[u8], tier: NodeTier) {
    let tier_name = tier.name();
    let color = match tier {
        NodeTier::Bronze => 0xFFCD7F32,
        NodeTier::Silver => 0xFFC0C0C0,
        NodeTier::Gold => 0xFFFFD700,
        NodeTier::Platinum => 0xFFE5E4E2,
        NodeTier::Diamond => 0xFF00FFFF,
    };

    let mut line = [0u8; 32];
    let plen = prefix.len().min(16);
    line[..plen].copy_from_slice(&prefix[..plen]);
    let tlen = tier_name.len().min(16);
    line[plen..plen + tlen].copy_from_slice(&tier_name[..tlen]);
    print_line(&line[..plen + tlen], color);
}

pub(super) fn print_number_line(prefix: &[u8], num: u32, suffix: &[u8]) {
    let mut line = [0u8; 48];
    let plen = prefix.len().min(24);
    line[..plen].copy_from_slice(&prefix[..plen]);

    let mut pos = plen;
    if num == 0 {
        line[pos] = b'0';
        pos += 1;
    } else {
        let mut n = num;
        let mut digits = [0u8; 12];
        let mut dpos = 0;
        while n > 0 {
            digits[dpos] = b'0' + (n % 10) as u8;
            n /= 10;
            dpos += 1;
        }
        for i in (0..dpos).rev() {
            line[pos] = digits[i];
            pos += 1;
        }
    }

    let slen = suffix.len().min(12);
    line[pos..pos + slen].copy_from_slice(&suffix[..slen]);
    pos += slen;

    print_line(&line[..pos], COLOR_TEXT);
}

pub(super) fn print_token_amount(prefix: &[u8], amount: &crate::daemon::types::TokenAmount) {
    let whole = amount.whole();
    let frac = (amount.frac() / 1_000_000_000_000_000) as u32;

    let mut line = [0u8; 48];
    let plen = prefix.len().min(16);
    line[..plen].copy_from_slice(&prefix[..plen]);

    let mut pos = plen;

    if whole == 0 {
        line[pos] = b'0';
        pos += 1;
    } else {
        let mut n = whole;
        let mut digits = [0u8; 20];
        let mut dpos = 0;
        while n > 0 {
            digits[dpos] = b'0' + (n % 10) as u8;
            n /= 10;
            dpos += 1;
        }
        for i in (0..dpos).rev() {
            line[pos] = digits[i];
            pos += 1;
        }
    }

    line[pos] = b'.';
    pos += 1;
    line[pos] = b'0' + ((frac / 100) % 10) as u8;
    pos += 1;
    line[pos] = b'0' + ((frac / 10) % 10) as u8;
    pos += 1;
    line[pos] = b'0' + (frac % 10) as u8;
    pos += 1;

    line[pos..pos + 4].copy_from_slice(b" NOX");
    pos += 4;

    print_line(&line[..pos], COLOR_ACCENT);
}

pub(super) fn print_bytes(prefix: &[u8], bytes: u64) {
    let (val, unit): (u32, &[u8]) = if bytes >= 1_073_741_824 {
        ((bytes / 1_073_741_824) as u32, b" GB")
    } else if bytes >= 1_048_576 {
        ((bytes / 1_048_576) as u32, b" MB")
    } else if bytes >= 1024 {
        ((bytes / 1024) as u32, b" KB")
    } else {
        (bytes as u32, b" B")
    };

    print_number_line(prefix, val, unit);
}
