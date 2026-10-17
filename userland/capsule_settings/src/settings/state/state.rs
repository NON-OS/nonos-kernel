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

use nonos_toolkit::widgets::Pointer;

use crate::settings::schema::ALL_FIELDS;
use crate::settings::section::{Section, SECTION_COUNT};
use crate::settings::ui::target::Target;
use crate::wifi::{DataPath, DriverStage, NetStatus, ScanNetwork, ScanStats, WifiInterface};

use super::cache::FieldValue;
use super::edit_buffer::EditBuffer;
use super::audio_output::AudioOutput;
use super::machine_key::MachineKey;
use super::status::Status;
use super::wifi_extra::WifiExtra;
pub use super::wifi_kinds::{WifiConnect, WifiScan};

pub const FIELD_SLOTS: usize = ALL_FIELDS.len();
/// The most WiFi adapters the panel lists at once.
pub const WIFI_MAX: usize = 8;
/// The most networks the panel shows from one scan.
pub const WIFI_NET_MAX: usize = 16;

pub struct State {
    pub policy_port: u32,
    pub policy_ready: bool,
    pub section: Section,
    pub cursor: [usize; SECTION_COUNT],
    /// Pixel scroll per section. The pane lays out cards of differing heights,
    /// so a row-index offset cannot address a position inside one.
    pub scroll_px: [u32; SECTION_COUNT],
    /// The titlebar search query. Non-empty replaces the section pane with
    /// results drawn from every section, so search answers where a setting
    /// lives rather than filtering the screen already open.
    pub search: EditBuffer,
    pub search_focused: bool,
    pub search_cursor: usize,
    pub search_scroll: u32,
    pub values: [FieldValue; FIELD_SLOTS],
    pub editing: bool,
    pub edit: EditBuffer,
    pub status: Status,
    pub wifi_adapters: [WifiInterface; WIFI_MAX],
    pub wifi_adapter_count: usize,
    pub wifi_cursor: usize,
    /// The networks the last scan found, and how many are valid.
    pub wifi_networks: [ScanNetwork; WIFI_NET_MAX],
    pub wifi_network_count: usize,
    /// Whether a scan has run and, if so, how it resolved.
    pub wifi_scan: WifiScan,
    /// The driver's radio bring-up stage from the last query, if it answered.
    pub wifi_stage: Option<DriverStage>,
    /// The driver's receive-pipeline counters from the last scan, so the panel can
    /// show where reception stops when no networks come back.
    pub wifi_stats: ScanStats,
    /// Whether the passphrase editor is open for the selected secured network.
    pub wifi_pass_active: bool,
    /// The passphrase is drawn as typed rather than as stars (Tab).
    pub wifi_pass_shown: bool,
    /// The passphrase being typed for a secured network.
    pub wifi_pass: EditBuffer,
    /// The outcome of the last connection attempt.
    pub wifi_connect: WifiConnect,
    /// The driver's data-path frame counts from the last refresh, so a stuck DHCP
    /// is legible: no TX means net_core handed nothing down, RX without parsed
    /// means the frames never decrypt.
    pub wifi_datapath: Option<DataPath>,
    /// What net_core reports: down, bound-but-no-address, or a bound lease. Splits
    /// "the stack never started" from "started but got no address".
    pub wifi_net: NetStatus,
    /// When `wifi_net` was last asked of the DHCP client, on the uptime clock
    /// (wifi/net_poll.rs).
    pub wifi_net_polled_ms: Option<i64>,
    /// The driver found, its link, and the saved networks by name.
    pub wifi: WifiExtra,
    /// What the kernel said the last time Security asked for the machine key.
    pub machine_key: MachineKey,
    /// What audio.server said the last time the Sound page asked.
    pub audio_output: AudioOutput,
    /// Window size as of the last paint. The window is resizable, so layout and
    /// hit tests read this rather than the manifest's starting size: against
    /// the constants, clicks below the original height were treated as the
    /// status bar and the control on the right of a widened window did nothing.
    pub win_w: u32,
    pub win_h: u32,
    /// The pointer over the content, fed by every move, press and release.
    pub pointer: Pointer,
    /// What is under the pointer, so a move repaints only when it changes.
    pub hover: Target,
}
