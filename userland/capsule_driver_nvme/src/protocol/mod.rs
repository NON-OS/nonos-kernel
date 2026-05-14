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

mod decode;
mod encode;
mod endpoint;
mod errno;
mod header;
mod limits;
mod ops;

pub use decode::decode_request;
pub use encode::{encode_response_header, write_status};
pub use endpoint::{KERNEL_REPLY_ENDPOINT, SERVICE_NAME};
pub use errno::E_INVAL;
pub use header::{Request, HDR_LEN, RESP_HDR_LEN};
pub use limits::{
    CONTROLLER_INFO_PAYLOAD_LEN, IDENTIFY_CONTROLLER_PAYLOAD_LEN, IDENTIFY_NAMESPACE_PAYLOAD_LEN,
    SMART_HEALTH_PAYLOAD_LEN, STATUS_LEN,
};
pub use ops::{
    OP_CONTROLLER_INFO, OP_HEALTHCHECK, OP_IDENTIFY_CONTROLLER, OP_IDENTIFY_NAMESPACE,
    OP_SMART_HEALTH,
};
