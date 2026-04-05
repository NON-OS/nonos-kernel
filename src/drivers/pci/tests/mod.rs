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

pub mod address;
pub mod bar;
pub mod constants;
pub mod errors;
pub mod types;

use crate::test::framework::TestSuite;

pub fn run_all() -> TestSuite {
    let mut suite = TestSuite::new("pci");

    // address tests (4 tests)
    suite.add_test("test_pci_address_creation", address::test_pci_address_creation);
    suite.add_test("test_pci_address_bdf_conversion", address::test_pci_address_bdf_conversion);
    suite.add_test("test_pci_address_display", address::test_pci_address_display);
    suite.add_test("test_config_address_calculation", address::test_config_address_calculation);

    // bar tests (4 tests)
    suite.add_test("test_bar_offset_calculation", bar::test_bar_offset_calculation);
    suite.add_test("test_pci_bar_properties", bar::test_pci_bar_properties);
    suite.add_test("test_bar_alignment_calculation", bar::test_bar_alignment_calculation);
    suite.add_test("test_bar_type_identification", bar::test_bar_type_identification);

    // constants tests (6 tests)
    suite.add_test("test_class_name_lookup", constants::test_class_name_lookup);
    suite.add_test("test_capability_name_lookup", constants::test_capability_name_lookup);
    suite.add_test("test_pcie_link_speed_string", constants::test_pcie_link_speed_string);
    suite.add_test("test_command_register_bits", constants::test_command_register_bits);
    suite.add_test("test_status_register_bits", constants::test_status_register_bits);
    suite.add_test("test_vendor_ids", constants::test_vendor_ids);

    // errors tests (3 tests)
    suite.add_test("test_error_display", errors::test_error_display);
    suite.add_test("test_error_classification", errors::test_error_classification);
    suite.add_test("test_security_level_ordering", errors::test_security_level_ordering);

    // types tests (13 tests)
    suite.add_test("test_class_code_methods", types::test_class_code_methods);
    suite.add_test("test_header_type_parsing", types::test_header_type_parsing);
    suite.add_test("test_capability_creation", types::test_capability_creation);
    suite.add_test("test_msi_message_creation", types::test_msi_message_creation);
    suite.add_test("test_device_id_matching", types::test_device_id_matching);
    suite.add_test("test_pcie_device_type_parsing", types::test_pcie_device_type_parsing);
    suite.add_test("test_pci_device_creation", types::test_pci_device_creation);
    suite.add_test("test_bridge_info_creation", types::test_bridge_info_creation);
    suite.add_test("test_msi_info_vectors", types::test_msi_info_vectors);
    suite.add_test("test_msix_info_vectors", types::test_msix_info_vectors);
    suite.add_test("test_power_management_info", types::test_power_management_info);
    suite.add_test("test_stats_snapshot", types::test_stats_snapshot);

    suite
}
