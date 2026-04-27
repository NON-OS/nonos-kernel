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

use super::super::error::{Ps2Error, Ps2Result};
use super::controller::Controller;
use super::mouse_commands::*;
use super::mouse_types::MouseType;

pub fn init_mouse(controller: &Controller) -> Ps2Result<MouseType> {
    if !controller.port2_working() {
        return Err(Ps2Error::MouseNotDetected);
    }
    let response = controller.send_command(2, CMD_RESET)?;
    if response != RESP_ACK {
        return Err(Ps2Error::InvalidResponse);
    }
    let self_test = controller.read_data()?;
    if self_test != RESP_SELF_TEST_PASS {
        return Err(Ps2Error::SelfTestFailed);
    }
    let _ = controller.read_data();
    let mouse_type = detect_type(controller)?;
    let _ = controller.send_command(2, CMD_SET_DEFAULTS);
    let _ = controller.send_command(2, CMD_ENABLE_REPORTING);
    Ok(mouse_type)
}

fn detect_type(controller: &Controller) -> Ps2Result<MouseType> {
    set_sample_rate(controller, 200)?;
    set_sample_rate(controller, 100)?;
    set_sample_rate(controller, 80)?;
    let id = get_device_id(controller)?;
    if id == DEVICE_ID_WHEEL || id == DEVICE_ID_5_BUTTON {
        set_sample_rate(controller, 200)?;
        set_sample_rate(controller, 200)?;
        set_sample_rate(controller, 80)?;
        let id2 = get_device_id(controller)?;
        if id2 == DEVICE_ID_5_BUTTON {
            return Ok(MouseType::FiveButton);
        }
        return Ok(MouseType::Wheel);
    }
    Ok(MouseType::Standard)
}

fn set_sample_rate(controller: &Controller, rate: u8) -> Ps2Result<()> {
    controller.write_port2(CMD_SET_SAMPLE_RATE)?;
    let _ = controller.read_data()?;
    controller.write_port2(rate)?;
    let _ = controller.read_data()?;
    Ok(())
}

fn get_device_id(controller: &Controller) -> Ps2Result<u8> {
    controller.write_port2(CMD_GET_DEVICE_ID)?;
    let _ = controller.read_data()?;
    controller.read_data()
}
