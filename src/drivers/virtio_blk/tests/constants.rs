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

#[test]
fn test_vendor_id() {
    assert_eq!(VIRTIO_BLK_VENDOR_ID, 0x1AF4);
}

#[test]
fn test_device_id_transitional() {
    assert_eq!(VIRTIO_BLK_DEVICE_ID_TRANSITIONAL, 0x1001);
}

#[test]
fn test_device_id_modern() {
    assert_eq!(VIRTIO_BLK_DEVICE_ID_MODERN, 0x1042);
}

#[test]
fn test_request_type_in() {
    assert_eq!(VIRTIO_BLK_T_IN, 0);
}

#[test]
fn test_request_type_out() {
    assert_eq!(VIRTIO_BLK_T_OUT, 1);
}

#[test]
fn test_request_type_flush() {
    assert_eq!(VIRTIO_BLK_T_FLUSH, 4);
}

#[test]
fn test_request_type_get_id() {
    assert_eq!(VIRTIO_BLK_T_GET_ID, 8);
}

#[test]
fn test_request_type_discard() {
    assert_eq!(VIRTIO_BLK_T_DISCARD, 11);
}

#[test]
fn test_request_type_write_zeroes() {
    assert_eq!(VIRTIO_BLK_T_WRITE_ZEROES, 13);
}

#[test]
fn test_status_ok() {
    assert_eq!(VIRTIO_BLK_S_OK, 0);
}

#[test]
fn test_status_ioerr() {
    assert_eq!(VIRTIO_BLK_S_IOERR, 1);
}

#[test]
fn test_status_unsupp() {
    assert_eq!(VIRTIO_BLK_S_UNSUPP, 2);
}

#[test]
fn test_feature_size_max() {
    assert_eq!(VIRTIO_BLK_F_SIZE_MAX, 1);
}

#[test]
fn test_feature_seg_max() {
    assert_eq!(VIRTIO_BLK_F_SEG_MAX, 2);
}

#[test]
fn test_feature_geometry() {
    assert_eq!(VIRTIO_BLK_F_GEOMETRY, 4);
}

#[test]
fn test_feature_ro() {
    assert_eq!(VIRTIO_BLK_F_RO, 5);
}

#[test]
fn test_feature_blk_size() {
    assert_eq!(VIRTIO_BLK_F_BLK_SIZE, 6);
}

#[test]
fn test_feature_flush() {
    assert_eq!(VIRTIO_BLK_F_FLUSH, 9);
}

#[test]
fn test_feature_discard() {
    assert_eq!(VIRTIO_BLK_F_DISCARD, 13);
}

#[test]
fn test_legacy_host_features() {
    assert_eq!(LEG_HOST_FEATURES, 0x00);
}

#[test]
fn test_legacy_guest_features() {
    assert_eq!(LEG_GUEST_FEATURES, 0x04);
}

#[test]
fn test_legacy_queue_pfn() {
    assert_eq!(LEG_QUEUE_PFN, 0x08);
}

#[test]
fn test_legacy_queue_num() {
    assert_eq!(LEG_QUEUE_NUM, 0x0C);
}

#[test]
fn test_legacy_queue_sel() {
    assert_eq!(LEG_QUEUE_SEL, 0x0E);
}

#[test]
fn test_legacy_notify() {
    assert_eq!(LEG_NOTIFY, 0x10);
}

#[test]
fn test_legacy_status() {
    assert_eq!(LEG_STATUS, 0x12);
}

#[test]
fn test_legacy_cfg_capacity() {
    assert_eq!(LEG_CFG_CAPACITY, 0x14);
}

#[test]
fn test_virtio_status_acknowledge() {
    assert_eq!(VIRTIO_STATUS_ACKNOWLEDGE, 1);
}

#[test]
fn test_virtio_status_driver() {
    assert_eq!(VIRTIO_STATUS_DRIVER, 2);
}

#[test]
fn test_virtio_status_driver_ok() {
    assert_eq!(VIRTIO_STATUS_DRIVER_OK, 4);
}

#[test]
fn test_virtio_status_features_ok() {
    assert_eq!(VIRTIO_STATUS_FEATURES_OK, 8);
}

#[test]
fn test_sector_size() {
    assert_eq!(SECTOR_SIZE, 512);
}

#[test]
fn test_max_sectors_per_request() {
    assert_eq!(MAX_SECTORS_PER_REQUEST, 256);
}

#[test]
fn test_default_timeout() {
    assert_eq!(DEFAULT_TIMEOUT_MS, 5000);
}

#[test]
fn test_status_values_unique() {
    assert_ne!(VIRTIO_BLK_S_OK, VIRTIO_BLK_S_IOERR);
    assert_ne!(VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_UNSUPP);
    assert_ne!(VIRTIO_BLK_S_OK, VIRTIO_BLK_S_UNSUPP);
}

#[test]
fn test_request_types_unique() {
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
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn test_virtio_status_bits_unique() {
    assert_eq!(VIRTIO_STATUS_ACKNOWLEDGE & VIRTIO_STATUS_DRIVER, 0);
    assert_eq!(VIRTIO_STATUS_DRIVER & VIRTIO_STATUS_DRIVER_OK, 0);
    assert_eq!(VIRTIO_STATUS_DRIVER_OK & VIRTIO_STATUS_FEATURES_OK, 0);
}

#[test]
fn test_legacy_register_spacing() {
    assert_eq!(LEG_GUEST_FEATURES - LEG_HOST_FEATURES, 4);
    assert_eq!(LEG_QUEUE_PFN - LEG_GUEST_FEATURES, 4);
    assert_eq!(LEG_QUEUE_NUM - LEG_QUEUE_PFN, 4);
}

#[test]
fn test_sector_size_is_power_of_two() {
    assert!(SECTOR_SIZE.is_power_of_two());
}
