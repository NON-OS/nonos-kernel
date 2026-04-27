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

pub use super::super::e1000::{
    get_e1000_device, get_stats as get_e1000_stats, init_e1000, is_present as e1000_is_present,
    E1000Device, E1000Stats,
};
pub use super::super::rtl8139::{
    get_rtl8139_device, get_stats as get_rtl8139_stats,
    handle_interrupt as rtl8139_handle_interrupt, init_rtl8139, is_present as rtl8139_is_present,
    Rtl8139Device, Rtl8139Stats,
};
pub use super::super::rtl8168::{
    get_rtl8168_device, get_stats as get_rtl8168_stats,
    handle_interrupt as rtl8168_handle_interrupt, init_rtl8168, is_present as rtl8168_is_present,
    Rtl8168Device, Rtl8168Stats,
};
pub use super::super::virtio_net::{
    get_virtio_net_device, init_virtio_net, NetworkStats, NetworkStatsSnapshot, VirtioNetDevice,
    VirtioNetError, VirtioNetHeader, VirtioNetInterface,
};
