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

use crate::network::onion::OnionError;
use super::types::X509Certificate;
use super::x509_der::DerParser;

pub(super) fn parse_validity(parser: &mut DerParser) -> Result<(u64, u64), OnionError> {
    parser.expect_sequence()?;
    let _validity_len = parser.read_length()?;
    let not_before = parse_time(parser)?;
    let not_after = parse_time(parser)?;
    Ok((not_before, not_after))
}

pub(super) fn parse_time(parser: &mut DerParser) -> Result<u64, OnionError> {
    let tag = parser.peek_tag().ok_or(OnionError::CertificateError)?;
    parser.offset += 1;
    let len = parser.read_length()?;
    let time_bytes = parser.read_bytes(len)?;

    let time_str = core::str::from_utf8(time_bytes).map_err(|_| OnionError::CertificateError)?;

    let (year, rest) = if tag == 0x17 {
        let y: u32 = time_str[..2].parse().map_err(|_| OnionError::CertificateError)?;
        let year = if y >= 50 { 1900 + y } else { 2000 + y };
        (year, &time_str[2..])
    } else if tag == 0x18 {
        let y: u32 = time_str[..4].parse().map_err(|_| OnionError::CertificateError)?;
        (y, &time_str[4..])
    } else {
        return Err(OnionError::CertificateError);
    };

    let month: u32 = rest[..2].parse().map_err(|_| OnionError::CertificateError)?;
    let day: u32 = rest[2..4].parse().map_err(|_| OnionError::CertificateError)?;
    let hour: u32 = rest[4..6].parse().map_err(|_| OnionError::CertificateError)?;
    let minute: u32 = rest[6..8].parse().map_err(|_| OnionError::CertificateError)?;
    let second: u32 = rest[8..10].parse().map_err(|_| OnionError::CertificateError)?;

    let days = days_since_epoch(year, month, day);
    let seconds = days * 86400 + (hour as u64) * 3600 + (minute as u64) * 60 + (second as u64);
    Ok(seconds * 1000)
}

fn days_since_epoch(year: u32, month: u32, day: u32) -> u64 {
    let y = year as u64;
    let m = month as u64;
    let d = day as u64;

    let days = (y - 1970) * 365 + (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400
        + (367 * m - 362) / 12
        + d
        - 1;

    // For months > February, adjust for the (367*m-362)/12 formula overcount:
    // leap year Feb has 29 days → subtract 1; non-leap Feb has 28 → subtract 2
    let leap_adjust = if m <= 2 {
        0
    } else if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) {
        1
    } else {
        2
    };

    days - leap_adjust
}

/// Minimum plausible system time (2020-01-01 00:00 UTC) in milliseconds.
/// If the kernel clock is below this threshold, it is clearly unset or wrong
/// and certificate time validation cannot be meaningfully enforced.
const MIN_PLAUSIBLE_TIME_MS: u64 = 1_577_836_800_000;

pub(crate) fn check_time_validity(cert: &X509Certificate, now_ms: u64) -> Result<(), OnionError> {
    crate::sys::serial::print(b"[CERT] not_before_ms=");
    crate::sys::serial::print_dec(cert.not_before_ms);
    crate::sys::serial::print(b" not_after_ms=");
    crate::sys::serial::print_dec(cert.not_after_ms);
    crate::sys::serial::print(b" now_ms=");
    crate::sys::serial::print_dec(now_ms);
    crate::sys::serial::println(b"");

    if now_ms < MIN_PLAUSIBLE_TIME_MS {
        crate::sys::serial::println(b"[CERT] system clock not set, skipping time check");
        return Ok(());
    }

    if now_ms < cert.not_before_ms || now_ms > cert.not_after_ms {
        return Err(OnionError::CertificateError);
    }
    Ok(())
}
