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

use super::state::MscDeviceState;
use super::csw::CommandStatusWrapper;

pub(super) fn send_scsi_command(
    state: &MscDeviceState,
    cmd: &[u8],
    data_in: Option<&mut [u8]>,
    data_out: Option<&[u8]>,
) -> Result<CommandStatusWrapper, &'static str> {
    let direction_in = data_in.is_some();
    let transfer_len = data_in.as_ref().map(|d| d.len())
        .or(data_out.map(|d| d.len()))
        .unwrap_or(0) as u32;

    let cbw = state.build_cbw(cmd, transfer_len, direction_in);

    if let Some(manager) = crate::drivers::usb::get_manager() {
        manager.bulk_out_transfer(state.slot_id, state.bulk_out_ep, cbw.as_bytes())?;
    } else {
        return Err("USB not initialized");
    }

    if let Some(data) = data_in {
        if let Some(manager) = crate::drivers::usb::get_manager() {
            let read_len = manager.bulk_in_transfer(state.slot_id, state.bulk_in_ep, data)?;
            if read_len < data.len() {
                data[read_len..].fill(0);
            }
        }
    } else if let Some(data) = data_out {
        if let Some(manager) = crate::drivers::usb::get_manager() {
            manager.bulk_out_transfer(state.slot_id, state.bulk_out_ep, data)?;
        }
    }

    let mut csw_buf = [0u8; 13];
    if let Some(manager) = crate::drivers::usb::get_manager() {
        manager.bulk_in_transfer(state.slot_id, state.bulk_in_ep, &mut csw_buf)?;
    }

    CommandStatusWrapper::from_bytes(&csw_buf).ok_or("Invalid CSW")
}
