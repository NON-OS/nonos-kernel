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

pub mod api;
mod hostname;
pub mod network;
mod persistence;
mod serialize;
pub(crate) mod state;
mod types;

pub use state::{get, get_mut, init, mark_modified, needs_save, reset_to_defaults};
pub use types::Settings;

pub use api::{
    animations_enabled,
    anonymous_mode,
    auto_lock_timeout,
    auto_wipe,
    brightness,
    cursor_size,
    developer_mode,
    font_size,
    hardware_crypto,
    high_contrast,
    // Kernel settings
    kernel_aslr,
    kernel_debug,
    kernel_hugepages,
    kernel_iommu,
    kernel_nx_bit,
    kernel_preempt,
    kernel_seccomp,
    kernel_serial,
    kernel_smap,
    kernel_smep,
    kernel_stack_guard,
    kernel_watchdog,
    keyboard_layout,
    language,
    mouse_sensitivity,
    notifications_enabled,
    nym_enabled,
    screen_timeout,
    set_animations_enabled,
    set_anonymous_mode,
    set_auto_lock_timeout,
    set_auto_wipe,
    set_brightness,
    set_cursor_size,
    set_developer_mode,
    set_font_size,
    set_hardware_crypto,
    set_high_contrast,
    set_kernel_aslr,
    set_kernel_debug,
    set_kernel_hugepages,
    set_kernel_iommu,
    set_kernel_nx_bit,
    set_kernel_preempt,
    set_kernel_seccomp,
    set_kernel_serial,
    set_kernel_smap,
    set_kernel_smep,
    set_kernel_stack_guard,
    set_kernel_watchdog,
    set_keyboard_layout,
    set_language,
    set_mouse_sensitivity,
    set_notifications_enabled,
    set_nym_enabled,
    set_screen_timeout,
    set_sound_enabled,
    set_system_keys_generated,
    set_theme,
    set_timezone,
    set_wifi_autoconnect,
    set_zk_attestation,
    sound_enabled,
    system_keys_generated,
    theme,
    timezone,
    wifi_autoconnect,
    zk_attestation,
};

pub use persistence::{load_from_disk, save_to_disk, SETTINGS_FILENAME};
pub use serialize::{deserialize, serialize};

pub use hostname::{
    get as get_hostname, get_domain as get_domainname, init as init_hostname, set as set_hostname,
    set_domain as set_domainname,
};
