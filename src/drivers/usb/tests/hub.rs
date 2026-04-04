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

use crate::drivers::usb::hub::*;

#[test]
fn test_hub_descriptor_type() {
    assert_eq!(DT_HUB, 0x29);
}

#[test]
fn test_ss_hub_descriptor_type() {
    assert_eq!(DT_SS_HUB, 0x2A);
}

#[test]
fn test_hub_request_get_status() {
    assert_eq!(HUB_REQ_GET_STATUS, 0x00);
}

#[test]
fn test_hub_request_clear_feature() {
    assert_eq!(HUB_REQ_CLEAR_FEATURE, 0x01);
}

#[test]
fn test_hub_request_set_feature() {
    assert_eq!(HUB_REQ_SET_FEATURE, 0x03);
}

#[test]
fn test_hub_request_get_descriptor() {
    assert_eq!(HUB_REQ_GET_DESCRIPTOR, 0x06);
}

#[test]
fn test_hub_request_set_descriptor() {
    assert_eq!(HUB_REQ_SET_DESCRIPTOR, 0x07);
}

#[test]
fn test_hub_request_clear_tt_buffer() {
    assert_eq!(HUB_REQ_CLEAR_TT_BUFFER, 0x08);
}

#[test]
fn test_hub_request_reset_tt() {
    assert_eq!(HUB_REQ_RESET_TT, 0x09);
}

#[test]
fn test_hub_request_get_tt_state() {
    assert_eq!(HUB_REQ_GET_TT_STATE, 0x0A);
}

#[test]
fn test_hub_request_stop_tt() {
    assert_eq!(HUB_REQ_STOP_TT, 0x0B);
}

#[test]
fn test_hub_feature_local_power() {
    assert_eq!(HUB_FEAT_C_HUB_LOCAL_POWER, 0);
}

#[test]
fn test_hub_feature_over_current() {
    assert_eq!(HUB_FEAT_C_HUB_OVER_CURRENT, 1);
}

#[test]
fn test_port_feature_connection() {
    assert_eq!(PORT_FEAT_CONNECTION, 0);
}

#[test]
fn test_port_feature_enable() {
    assert_eq!(PORT_FEAT_ENABLE, 1);
}

#[test]
fn test_port_feature_suspend() {
    assert_eq!(PORT_FEAT_SUSPEND, 2);
}

#[test]
fn test_port_feature_over_current() {
    assert_eq!(PORT_FEAT_OVER_CURRENT, 3);
}

#[test]
fn test_port_feature_reset() {
    assert_eq!(PORT_FEAT_RESET, 4);
}

#[test]
fn test_port_feature_power() {
    assert_eq!(PORT_FEAT_POWER, 8);
}

#[test]
fn test_port_feature_lowspeed() {
    assert_eq!(PORT_FEAT_LOWSPEED, 9);
}

#[test]
fn test_port_feature_c_connection() {
    assert_eq!(PORT_FEAT_C_CONNECTION, 16);
}

#[test]
fn test_port_feature_c_enable() {
    assert_eq!(PORT_FEAT_C_ENABLE, 17);
}

#[test]
fn test_port_feature_c_suspend() {
    assert_eq!(PORT_FEAT_C_SUSPEND, 18);
}

#[test]
fn test_port_feature_c_over_current() {
    assert_eq!(PORT_FEAT_C_OVER_CURRENT, 19);
}

#[test]
fn test_port_feature_c_reset() {
    assert_eq!(PORT_FEAT_C_RESET, 20);
}

#[test]
fn test_port_status_connection() {
    assert_eq!(PORT_STAT_CONNECTION, 1 << 0);
}

#[test]
fn test_port_status_enable() {
    assert_eq!(PORT_STAT_ENABLE, 1 << 1);
}

#[test]
fn test_port_status_suspend() {
    assert_eq!(PORT_STAT_SUSPEND, 1 << 2);
}

#[test]
fn test_port_status_overcurrent() {
    assert_eq!(PORT_STAT_OVERCURRENT, 1 << 3);
}

#[test]
fn test_port_status_reset() {
    assert_eq!(PORT_STAT_RESET, 1 << 4);
}

#[test]
fn test_port_status_power() {
    assert_eq!(PORT_STAT_POWER, 1 << 8);
}

#[test]
fn test_port_status_low_speed() {
    assert_eq!(PORT_STAT_LOW_SPEED, 1 << 9);
}

#[test]
fn test_port_status_high_speed() {
    assert_eq!(PORT_STAT_HIGH_SPEED, 1 << 10);
}

#[test]
fn test_port_status_test() {
    assert_eq!(PORT_STAT_TEST, 1 << 11);
}

#[test]
fn test_port_status_indicator() {
    assert_eq!(PORT_STAT_INDICATOR, 1 << 12);
}

#[test]
fn test_hub_char_lpsm_mask() {
    assert_eq!(HUB_CHAR_LPSM_MASK, 0x0003);
}

#[test]
fn test_hub_char_compound() {
    assert_eq!(HUB_CHAR_COMPOUND, 0x0004);
}

#[test]
fn test_hub_char_ocpm_mask() {
    assert_eq!(HUB_CHAR_OCPM_MASK, 0x0018);
}

#[test]
fn test_hub_char_tttt_mask() {
    assert_eq!(HUB_CHAR_TTTT_MASK, 0x0060);
}

#[test]
fn test_hub_char_portind() {
    assert_eq!(HUB_CHAR_PORTIND, 0x0080);
}

#[test]
fn test_max_hub_ports() {
    assert_eq!(MAX_HUB_PORTS, 15);
}

#[test]
fn test_hub_debounce_ms() {
    assert_eq!(HUB_DEBOUNCE_MS, 100);
}

#[test]
fn test_hub_reset_ms() {
    assert_eq!(HUB_RESET_MS, 50);
}

#[test]
fn test_hub_power_on_delay_ms() {
    assert_eq!(HUB_POWER_ON_DELAY_MS, 100);
}

#[test]
fn test_feat_port_power() {
    assert_eq!(FEAT_PORT_POWER, PORT_FEAT_POWER as u16);
}

#[test]
fn test_feat_port_reset() {
    assert_eq!(FEAT_PORT_RESET, PORT_FEAT_RESET as u16);
}

#[test]
fn test_feat_port_enable() {
    assert_eq!(FEAT_PORT_ENABLE, PORT_FEAT_ENABLE as u16);
}

#[test]
fn test_feat_c_port_connection() {
    assert_eq!(FEAT_C_PORT_CONNECTION, PORT_FEAT_C_CONNECTION as u16);
}

#[test]
fn test_port_status_bits_unique() {
    let statuses = [
        PORT_STAT_CONNECTION,
        PORT_STAT_ENABLE,
        PORT_STAT_SUSPEND,
        PORT_STAT_OVERCURRENT,
        PORT_STAT_RESET,
        PORT_STAT_POWER,
        PORT_STAT_LOW_SPEED,
        PORT_STAT_HIGH_SPEED,
    ];

    for i in 0..statuses.len() {
        for j in (i + 1)..statuses.len() {
            assert_ne!(statuses[i], statuses[j]);
        }
    }
}
