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
use crate::test::framework::TestResult;

pub(crate) fn test_hub_descriptor_type() -> TestResult {
    if DT_HUB != 0x29 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ss_hub_descriptor_type() -> TestResult {
    if DT_SS_HUB != 0x2A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_get_status() -> TestResult {
    if HUB_REQ_GET_STATUS != 0x00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_clear_feature() -> TestResult {
    if HUB_REQ_CLEAR_FEATURE != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_set_feature() -> TestResult {
    if HUB_REQ_SET_FEATURE != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_get_descriptor() -> TestResult {
    if HUB_REQ_GET_DESCRIPTOR != 0x06 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_set_descriptor() -> TestResult {
    if HUB_REQ_SET_DESCRIPTOR != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_clear_tt_buffer() -> TestResult {
    if HUB_REQ_CLEAR_TT_BUFFER != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_reset_tt() -> TestResult {
    if HUB_REQ_RESET_TT != 0x09 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_get_tt_state() -> TestResult {
    if HUB_REQ_GET_TT_STATE != 0x0A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_request_stop_tt() -> TestResult {
    if HUB_REQ_STOP_TT != 0x0B {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_feature_local_power() -> TestResult {
    if HUB_FEAT_C_HUB_LOCAL_POWER != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_feature_over_current() -> TestResult {
    if HUB_FEAT_C_HUB_OVER_CURRENT != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_connection() -> TestResult {
    if PORT_FEAT_CONNECTION != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_enable() -> TestResult {
    if PORT_FEAT_ENABLE != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_suspend() -> TestResult {
    if PORT_FEAT_SUSPEND != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_over_current() -> TestResult {
    if PORT_FEAT_OVER_CURRENT != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_reset() -> TestResult {
    if PORT_FEAT_RESET != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_power() -> TestResult {
    if PORT_FEAT_POWER != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_lowspeed() -> TestResult {
    if PORT_FEAT_LOWSPEED != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_c_connection() -> TestResult {
    if PORT_FEAT_C_CONNECTION != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_c_enable() -> TestResult {
    if PORT_FEAT_C_ENABLE != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_c_suspend() -> TestResult {
    if PORT_FEAT_C_SUSPEND != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_c_over_current() -> TestResult {
    if PORT_FEAT_C_OVER_CURRENT != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_feature_c_reset() -> TestResult {
    if PORT_FEAT_C_RESET != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_connection() -> TestResult {
    if PORT_STAT_CONNECTION != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_enable() -> TestResult {
    if PORT_STAT_ENABLE != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_suspend() -> TestResult {
    if PORT_STAT_SUSPEND != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_overcurrent() -> TestResult {
    if PORT_STAT_OVERCURRENT != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_reset() -> TestResult {
    if PORT_STAT_RESET != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_power() -> TestResult {
    if PORT_STAT_POWER != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_low_speed() -> TestResult {
    if PORT_STAT_LOW_SPEED != 1 << 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_high_speed() -> TestResult {
    if PORT_STAT_HIGH_SPEED != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_test() -> TestResult {
    if PORT_STAT_TEST != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_indicator() -> TestResult {
    if PORT_STAT_INDICATOR != 1 << 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_char_lpsm_mask() -> TestResult {
    if HUB_CHAR_LPSM_MASK != 0x0003 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_char_compound() -> TestResult {
    if HUB_CHAR_COMPOUND != 0x0004 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_char_ocpm_mask() -> TestResult {
    if HUB_CHAR_OCPM_MASK != 0x0018 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_char_tttt_mask() -> TestResult {
    if HUB_CHAR_TTTT_MASK != 0x0060 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_char_portind() -> TestResult {
    if HUB_CHAR_PORTIND != 0x0080 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_hub_ports() -> TestResult {
    if MAX_HUB_PORTS != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_debounce_ms() -> TestResult {
    if HUB_DEBOUNCE_MS != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_reset_ms() -> TestResult {
    if HUB_RESET_MS != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hub_power_on_delay_ms() -> TestResult {
    if HUB_POWER_ON_DELAY_MS != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feat_port_power() -> TestResult {
    if FEAT_PORT_POWER != PORT_FEAT_POWER as u16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feat_port_reset() -> TestResult {
    if FEAT_PORT_RESET != PORT_FEAT_RESET as u16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feat_port_enable() -> TestResult {
    if FEAT_PORT_ENABLE != PORT_FEAT_ENABLE as u16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_feat_c_port_connection() -> TestResult {
    if FEAT_C_PORT_CONNECTION != PORT_FEAT_C_CONNECTION as u16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_port_status_bits_unique() -> TestResult {
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
            if statuses[i] == statuses[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
