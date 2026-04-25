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

use crate::drivers::virtio_blk::constants::*;
use crate::test::framework::TestResult;

pub(crate) fn test_vendor_id() -> TestResult {
    if VIRTIO_BLK_VENDOR_ID != 0x1AF4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_transitional() -> TestResult {
    if VIRTIO_BLK_DEVICE_ID_TRANSITIONAL != 0x1001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_id_modern() -> TestResult {
    if VIRTIO_BLK_DEVICE_ID_MODERN != 0x1042 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_type_in() -> TestResult {
    if VIRTIO_BLK_T_IN != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_type_out() -> TestResult {
    if VIRTIO_BLK_T_OUT != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_type_flush() -> TestResult {
    if VIRTIO_BLK_T_FLUSH != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_type_get_id() -> TestResult {
    if VIRTIO_BLK_T_GET_ID != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_type_discard() -> TestResult {
    if VIRTIO_BLK_T_DISCARD != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_type_write_zeroes() -> TestResult {
    if VIRTIO_BLK_T_WRITE_ZEROES != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_ok() -> TestResult {
    if VIRTIO_BLK_S_OK != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_ioerr() -> TestResult {
    if VIRTIO_BLK_S_IOERR != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_unsupp() -> TestResult {
    if VIRTIO_BLK_S_UNSUPP != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_size_max() -> TestResult {
    if VIRTIO_BLK_F_SIZE_MAX != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_seg_max() -> TestResult {
    if VIRTIO_BLK_F_SEG_MAX != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_geometry() -> TestResult {
    if VIRTIO_BLK_F_GEOMETRY != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_ro() -> TestResult {
    if VIRTIO_BLK_F_RO != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_blk_size() -> TestResult {
    if VIRTIO_BLK_F_BLK_SIZE != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_flush() -> TestResult {
    if VIRTIO_BLK_F_FLUSH != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feature_discard() -> TestResult {
    if VIRTIO_BLK_F_DISCARD != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_host_features() -> TestResult {
    if LEG_HOST_FEATURES != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_guest_features() -> TestResult {
    if LEG_GUEST_FEATURES != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_queue_pfn() -> TestResult {
    if LEG_QUEUE_PFN != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_queue_num() -> TestResult {
    if LEG_QUEUE_NUM != 0x0C {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_queue_sel() -> TestResult {
    if LEG_QUEUE_SEL != 0x0E {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_notify() -> TestResult {
    if LEG_NOTIFY != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_status() -> TestResult {
    if LEG_STATUS != 0x12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_cfg_capacity() -> TestResult {
    if LEG_CFG_CAPACITY != 0x14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_acknowledge() -> TestResult {
    if VIRTIO_STATUS_ACKNOWLEDGE != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_driver() -> TestResult {
    if VIRTIO_STATUS_DRIVER != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_driver_ok() -> TestResult {
    if VIRTIO_STATUS_DRIVER_OK != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_features_ok() -> TestResult {
    if VIRTIO_STATUS_FEATURES_OK != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sector_size() -> TestResult {
    if SECTOR_SIZE != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_sectors_per_request() -> TestResult {
    if MAX_SECTORS_PER_REQUEST != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_timeout() -> TestResult {
    if DEFAULT_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_values_unique() -> TestResult {
    if VIRTIO_BLK_S_OK == VIRTIO_BLK_S_IOERR {
        return TestResult::Fail;
    }
    if VIRTIO_BLK_S_IOERR == VIRTIO_BLK_S_UNSUPP {
        return TestResult::Fail;
    }
    if VIRTIO_BLK_S_OK == VIRTIO_BLK_S_UNSUPP {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_types_unique() -> TestResult {
    let types = [
        VIRTIO_BLK_T_IN,
        VIRTIO_BLK_T_OUT,
        VIRTIO_BLK_T_FLUSH,
        VIRTIO_BLK_T_GET_ID,
        VIRTIO_BLK_T_DISCARD,
        VIRTIO_BLK_T_WRITE_ZEROES,
    ];

    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            if types[i] == types[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_virtio_status_bits_unique() -> TestResult {
    if VIRTIO_STATUS_ACKNOWLEDGE & VIRTIO_STATUS_DRIVER != 0 {
        return TestResult::Fail;
    }
    if VIRTIO_STATUS_DRIVER & VIRTIO_STATUS_DRIVER_OK != 0 {
        return TestResult::Fail;
    }
    if VIRTIO_STATUS_DRIVER_OK & VIRTIO_STATUS_FEATURES_OK != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_register_spacing() -> TestResult {
    if LEG_GUEST_FEATURES - LEG_HOST_FEATURES != 4 {
        return TestResult::Fail;
    }
    if LEG_QUEUE_PFN - LEG_GUEST_FEATURES != 4 {
        return TestResult::Fail;
    }
    if LEG_QUEUE_NUM - LEG_QUEUE_PFN != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sector_size_is_power_of_two() -> TestResult {
    if !SECTOR_SIZE.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
