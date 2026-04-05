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

pub mod codec;
pub mod constants;
pub mod error;
pub mod types;

use crate::test::framework::TestSuite;

pub fn run_all() -> TestSuite {
    let mut suite = TestSuite::new("audio");

    // codec tests (19 tests)
    suite.add_test("test_compose_verb", codec::test_compose_verb);
    suite.add_test("test_capabilities_from_gcap", codec::test_capabilities_from_gcap);
    suite.add_test("test_vendor_name", codec::test_vendor_name);
    suite.add_test("test_codec_info_empty", codec::test_codec_info_empty);
    suite.add_test("test_codec_info_copy", codec::test_codec_info_copy);
    suite.add_test("test_widget_info_default", codec::test_widget_info_default);
    suite.add_test("test_widget_info_has_out_amp", codec::test_widget_info_has_out_amp);
    suite.add_test("test_widget_info_has_in_amp", codec::test_widget_info_has_in_amp);
    suite.add_test("test_widget_info_is_output_pin", codec::test_widget_info_is_output_pin);
    suite.add_test("test_widget_info_is_input_pin", codec::test_widget_info_is_input_pin);
    suite.add_test("test_widget_info_pin_device_type", codec::test_widget_info_pin_device_type);
    suite.add_test("test_widget_info_pin_connectivity", codec::test_widget_info_pin_connectivity);
    suite.add_test("test_widget_info_is_connected", codec::test_widget_info_is_connected);
    suite.add_test("test_widget_info_amp_steps", codec::test_widget_info_amp_steps);
    suite.add_test("test_audio_path_default", codec::test_audio_path_default);
    suite.add_test("test_audio_path_copy", codec::test_audio_path_copy);
    suite.add_test("test_codec_paths_default", codec::test_codec_paths_default);
    suite.add_test("test_device_name", codec::test_device_name);
    suite.add_test("test_vendor_name_extended", codec::test_vendor_name_extended);

    // constants tests (11 tests)
    suite.add_test("test_global_register_offsets", constants::test_global_register_offsets);
    suite.add_test("test_corb_rirb_offsets", constants::test_corb_rirb_offsets);
    suite.add_test("test_immediate_command_offsets", constants::test_immediate_command_offsets);
    suite.add_test("test_stream_descriptor_offsets", constants::test_stream_descriptor_offsets);
    suite.add_test("test_gctl_bits", constants::test_gctl_bits);
    suite.add_test("test_stream_ctl_bits", constants::test_stream_ctl_bits);
    suite.add_test("test_buffer_sizes", constants::test_buffer_sizes);
    suite.add_test("test_default_audio_constants", constants::test_default_audio_constants);
    suite.add_test("test_spin_timeouts", constants::test_spin_timeouts);
    suite.add_test("test_pci_class_codes", constants::test_pci_class_codes);
    suite.add_test("test_parameter_constants", constants::test_parameter_constants);

    // error tests (4 tests)
    suite.add_test("test_audio_error_display", error::test_audio_error_display);
    suite.add_test("test_audio_error_variants", error::test_audio_error_variants);
    suite.add_test("test_audio_error_equality", error::test_audio_error_equality);
    suite.add_test("test_audio_error_from_str", error::test_audio_error_from_str);

    // types tests (10 tests)
    suite.add_test("test_bdl_entry_size", types::test_bdl_entry_size);
    suite.add_test("test_bdl_entry_new", types::test_bdl_entry_new);
    suite.add_test("test_bdl_entry_zeroed", types::test_bdl_entry_zeroed);
    suite.add_test("test_bdl_entry_phys_addr", types::test_bdl_entry_phys_addr);
    suite.add_test("test_audio_stats_default", types::test_audio_stats_default);
    suite.add_test("test_audio_stats_copy", types::test_audio_stats_copy);
    suite.add_test("test_audio_format_default", types::test_audio_format_default);
    suite.add_test("test_audio_format_bytes_per_sample", types::test_audio_format_bytes_per_sample);
    suite.add_test("test_audio_format_bytes_per_second", types::test_audio_format_bytes_per_second);
    suite.add_test("test_audio_format_to_hda", types::test_audio_format_to_hda);
    suite.add_test("test_stream_state_default", types::test_stream_state_default);

    suite
}
