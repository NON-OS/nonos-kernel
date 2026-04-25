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

use super::super::constants::*;
use super::super::inquiry::InquiryResponse;
use super::super::scsi::send_scsi_command;
use super::super::state::MscDeviceState;

pub fn inquiry(state: &MscDeviceState) -> Result<InquiryResponse, &'static str> {
    let cmd = [SCSI_INQUIRY, 0, 0, 0, 36, 0];
    let mut data = [0u8; 36];
    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Inquiry failed");
    }
    InquiryResponse::parse(&data).ok_or("Invalid inquiry response")
}
