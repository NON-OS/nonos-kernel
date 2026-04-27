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

pub mod api;
pub mod constants;
pub mod device_types;
pub mod queue_layout;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("virtio_rng");

    // constants tests
    suite.add_test("test_virtio_vendor_id", constants::test_virtio_vendor_id);
    suite.add_test("test_virtio_rng_device_ids", constants::test_virtio_rng_device_ids);
    suite.add_test("test_device_ids_are_distinct", constants::test_device_ids_are_distinct);
    suite.add_test(
        "test_device_ids_are_in_virtio_range",
        constants::test_device_ids_are_in_virtio_range,
    );
    suite.add_test(
        "test_is_available_initially_false",
        constants::test_is_available_initially_false,
    );

    // api tests
    suite.add_test("test_is_available_before_init", api::test_is_available_before_init);
    suite.add_test(
        "test_get_random_bytes_fails_before_init",
        api::test_get_random_bytes_fails_before_init,
    );
    suite.add_test(
        "test_get_random_bytes_empty_buf_fails_before_init",
        api::test_get_random_bytes_empty_buf_fails_before_init,
    );
    suite.add_test("test_fill_random_empty_buf_ok", api::test_fill_random_empty_buf_ok);
    suite.add_test("test_fill_random_fails_before_init", api::test_fill_random_fails_before_init);

    suite.run()
}
