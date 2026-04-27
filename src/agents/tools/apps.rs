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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub(super) fn register() {
    super::register_tool(b"list_apps", b"List installed apps", tool_list_apps);
    super::register_tool(b"notify", b"Send notification: message", tool_notify);
    super::register_tool(b"open_app", b"Open app by name", tool_open_app);
}

fn tool_list_apps(_args: &[u8]) -> Vec<u8> {
    let apps = crate::sdk::registry::list_apps();
    if apps.is_empty() {
        return b"No apps installed".to_vec();
    }
    let mut out = String::from("Installed Apps\n==============\n");
    for app in apps {
        let name_len = app.manifest.name.iter().position(|&c| c == 0).unwrap_or(64);
        let name = core::str::from_utf8(&app.manifest.name[..name_len]).unwrap_or("?");
        let ver_len = app.manifest.version.iter().position(|&c| c == 0).unwrap_or(16);
        let ver = core::str::from_utf8(&app.manifest.version[..ver_len]).unwrap_or("?");
        out.push_str(&format!("  {} (v{})\n", name, ver));
    }
    out.into_bytes()
}

fn tool_notify(args: &[u8]) -> Vec<u8> {
    let msg = core::str::from_utf8(args).unwrap_or("Notification");
    crate::graphics::window::notify_success(msg.as_bytes());
    b"Notification sent".to_vec()
}

fn tool_open_app(args: &[u8]) -> Vec<u8> {
    let name = core::str::from_utf8(args).unwrap_or("").trim().to_lowercase();
    let wtype = match name.as_str() {
        "terminal" | "shell" => crate::graphics::window::WindowType::Terminal,
        "files" | "filemanager" => crate::graphics::window::WindowType::FileManager,
        "editor" | "text" => crate::graphics::window::WindowType::TextEditor,
        "wallet" => crate::graphics::window::WindowType::Wallet,
        "settings" => crate::graphics::window::WindowType::Settings,
        "browser" => crate::graphics::window::WindowType::Browser,
        "marketplace" => crate::graphics::window::WindowType::Marketplace,
        _ => return format!("Unknown app: {}", name).into_bytes(),
    };
    crate::graphics::window::open(wtype);
    format!("Opened {}", name).into_bytes()
}
