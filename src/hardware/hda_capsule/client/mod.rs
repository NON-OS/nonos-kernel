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

mod codec_list;
mod codec_mask;
mod controller_info;
mod healthcheck;
mod seq;
mod status_map;
mod stream_layout;
mod transport;

pub(super) use transport::REPLY_INBOX;

pub use codec_list::{codec_list, HdaCodecInfo};
pub use codec_mask::{codec_mask, HdaCodecMask};
pub use controller_info::{controller_info, HdaControllerInfo};
pub use healthcheck::healthcheck;
pub use stream_layout::{stream_layout, HdaStreamInfo};
