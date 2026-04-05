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

pub mod constants;
pub mod types;

use crate::test::framework::TestSuite;

pub fn run_all() -> TestSuite {
    let mut suite = TestSuite::new("virtio_blk");

    // constants tests
    suite.add_test("test_vendor_id", constants::test_vendor_id);
    suite.add_test("test_device_id_transitional", constants::test_device_id_transitional);
    suite.add_test("test_device_id_modern", constants::test_device_id_modern);
    suite.add_test("test_request_type_in", constants::test_request_type_in);
    suite.add_test("test_request_type_out", constants::test_request_type_out);
    suite.add_test("test_request_type_flush", constants::test_request_type_flush);
    suite.add_test("test_request_type_get_id", constants::test_request_type_get_id);
    suite.add_test("test_request_type_discard", constants::test_request_type_discard);
    suite.add_test("test_request_type_write_zeroes", constants::test_request_type_write_zeroes);
    suite.add_test("test_status_ok", constants::test_status_ok);
    suite.add_test("test_status_ioerr", constants::test_status_ioerr);
    suite.add_test("test_status_unsupp", constants::test_status_unsupp);
    suite.add_test("test_feature_size_max", constants::test_feature_size_max);
    suite.add_test("test_feature_seg_max", constants::test_feature_seg_max);
    suite.add_test("test_feature_geometry", constants::test_feature_geometry);
    suite.add_test("test_feature_ro", constants::test_feature_ro);
    suite.add_test("test_feature_blk_size", constants::test_feature_blk_size);
    suite.add_test("test_feature_flush", constants::test_feature_flush);
    suite.add_test("test_feature_discard", constants::test_feature_discard);
    suite.add_test("test_legacy_host_features", constants::test_legacy_host_features);
    suite.add_test("test_legacy_guest_features", constants::test_legacy_guest_features);
    suite.add_test("test_legacy_queue_pfn", constants::test_legacy_queue_pfn);
    suite.add_test("test_legacy_queue_num", constants::test_legacy_queue_num);
    suite.add_test("test_legacy_queue_sel", constants::test_legacy_queue_sel);
    suite.add_test("test_legacy_notify", constants::test_legacy_notify);
    suite.add_test("test_legacy_status", constants::test_legacy_status);
    suite.add_test("test_legacy_cfg_capacity", constants::test_legacy_cfg_capacity);
    suite.add_test("test_virtio_status_acknowledge", constants::test_virtio_status_acknowledge);
    suite.add_test("test_virtio_status_driver", constants::test_virtio_status_driver);
    suite.add_test("test_virtio_status_driver_ok", constants::test_virtio_status_driver_ok);
    suite.add_test("test_virtio_status_features_ok", constants::test_virtio_status_features_ok);
    suite.add_test("test_sector_size", constants::test_sector_size);
    suite.add_test("test_max_sectors_per_request", constants::test_max_sectors_per_request);
    suite.add_test("test_default_timeout", constants::test_default_timeout);
    suite.add_test("test_status_values_unique", constants::test_status_values_unique);
    suite.add_test("test_request_types_unique", constants::test_request_types_unique);
    suite.add_test("test_virtio_status_bits_unique", constants::test_virtio_status_bits_unique);
    suite.add_test("test_legacy_register_spacing", constants::test_legacy_register_spacing);
    suite.add_test("test_sector_size_is_power_of_two", constants::test_sector_size_is_power_of_two);

    // types tests
    suite.add_test("test_module_exists", types::test_module_exists);
    suite.add_test("test_basic_constants", types::test_basic_constants);
    suite.add_test("test_basic_operations", types::test_basic_operations);

    suite
}
