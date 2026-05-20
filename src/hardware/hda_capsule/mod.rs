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

//! Kernel-side glue for the Intel HDA userland driver capsule.
//! The kernel embeds and spawns the signed capsule, then speaks the
//! controller/codec inventory IPC contract. BAR0 mapping, IRQ acking,
//! controller reset release, immediate codec commands, and stream
//! layout discovery stay inside `driver.hda0`.

mod capability;
pub mod client;
pub(crate) mod embed;
mod error;
mod protocol;
mod spawn;
mod state;

pub use client::{
    codec_list, codec_mask, controller_info, healthcheck, stream_layout, HdaCodecInfo,
    HdaCodecMask, HdaControllerInfo, HdaStreamInfo,
};
pub use error::DriverHdaError;
pub use spawn::{spawn_driver_hda_capsule, SpawnError};
pub use state::shared_state;
