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

use crate::setup::prime::{overlay::Overlay, peers::Peers};
use crate::state::{new_taskbar_state, Context, ToastQueue, TrayTable};

pub fn build_context(
    peers: &Peers,
    overlay: &Overlay,
    desk: &Overlay,
    wallpaper_policy_sent: bool,
) -> Context {
    Context {
        compositor_port: peers.compositor_port,
        wm_port: peers.wm_port,
        input_router_port: peers.input_router_port,
        wallpaper_port: peers.wallpaper_port,
        wallpaper_policy_sent,
        input_kind_mask: super::input_mask::SHELL_INPUT_MASK,
        input_ready: false,
        wm_notify_ready: false,
        width: overlay.width,
        height: overlay.height,
        scale: crate::state::scale::quarters_for(overlay.width, overlay.height),
        stride: overlay.stride,
        backing_va: overlay.backing_va,
        desk_va: desk.backing_va,
        chrome_va: overlay.backing_va,
        back: alloc::vec::Vec::new(),
        grab_held: 0,
        tray: TrayTable::new(),
        taskbar: new_taskbar_state(),
        launchpad: false,
        launchpad_query: alloc::string::String::new(),
        launchpad_page: 0,
        launchpad_wheel: crate::state::launchpad_wheel::PageWheel::default(),
        launchpad_view: alloc::vec::Vec::new(),
        toasts: ToastQueue::new(),
        toast_layer_live: false,
        toasts_drawn: 0,
        toasts_synced: 0,
        toast_window: None,
        net_was_online: false,
        clock_24h: true,
        tz_hours: 0,
        policy_port: 0,
        policy_gap: crate::state::quiet_gap::QuietGap::new(),
        installer_gap: crate::state::quiet_gap::QuietGap::new(),
        next_request_id: 2,
        desktop_items: alloc::vec::Vec::new(),
        installed_apps: alloc::vec::Vec::new(),
        installed_apps_loaded: false,
        pkg_files: alloc::vec::Vec::new(),
        pkg_files_loaded: false,
        installed_pids: alloc::collections::BTreeMap::new(),
        launch: None,
        desktop_menu: None,
        menubar: crate::state::new_menubar_state(),
        menu_hover: None,
        menu_target: None,
        rename: None,
        rename_buf: alloc::string::String::new(),
        drag_from: None,
        drag_moved: false,
        drag_x: 0,
        drag_y: 0,
        pending_open: alloc::collections::BTreeMap::new(),
        pending_command: None,
        pending_consent: None,
        pending_pkg_install: None,
        live_prompt: crate::state::live_prompt::LivePrompt::new(),
        pending_delete: crate::state::delete_prompt::DeletePrompt::new(),
        dialog_focus: crate::state::dialog_keys::DialogFocus::new(),
        palette: crate::render::palette::current(),
    }
}
