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

use crate::drivers::virtio_rng;
use crate::test::framework::TestResult;

// is_available()

pub(crate) fn test_is_available_before_init() -> TestResult {
    // In the test harness, init() is never called, so the device
    // should not report as available.
    if virtio_rng::is_available() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

// get_random_bytes() without init

pub(crate) fn test_get_random_bytes_fails_before_init() -> TestResult {
    let mut buf = [0u8; 32];
    let result = virtio_rng::get_random_bytes(&mut buf);
    if result.is_ok() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != "virtio-rng not available" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_random_bytes_empty_buf_fails_before_init() -> TestResult {
    let mut buf = [0u8; 0];
    // Even an empty buffer should fail - device not available
    let result = virtio_rng::get_random_bytes(&mut buf);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

// fill_random() without init

pub(crate) fn test_fill_random_empty_buf_ok() -> TestResult {
    // Empty buffer is a no-op - should succeed even without device
    let mut buf = [0u8; 0];
    let result = virtio_rng::fill_random(&mut buf);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_fill_random_fails_before_init() -> TestResult {
    let mut buf = [0u8; 32];
    let result = virtio_rng::fill_random(&mut buf);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
