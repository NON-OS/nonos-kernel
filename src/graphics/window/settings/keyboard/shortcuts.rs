// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pub(super) struct Shortcut {
    pub name: &'static str,
    pub keys: &'static str,
}

pub(super) static SHORTCUTS: &[Shortcut] = &[
    Shortcut { name: "Copy", keys: "Ctrl+C" },
    Shortcut { name: "Paste", keys: "Ctrl+V" },
    Shortcut { name: "Cut", keys: "Ctrl+X" },
    Shortcut { name: "Undo", keys: "Ctrl+Z" },
    Shortcut { name: "Redo", keys: "Ctrl+Y" },
    Shortcut { name: "Save", keys: "Ctrl+S" },
    Shortcut { name: "Close Window", keys: "Alt+F4" },
    Shortcut { name: "Switch Window", keys: "Alt+Tab" },
    Shortcut { name: "Minimize", keys: "Super+D" },
    Shortcut { name: "Maximize", keys: "Super+Up" },
    Shortcut { name: "Terminal", keys: "Ctrl+Alt+T" },
    Shortcut { name: "File Manager", keys: "Super+E" },
    Shortcut { name: "Settings", keys: "Super+I" },
    Shortcut { name: "Lock Screen", keys: "Super+L" },
    Shortcut { name: "Screenshot", keys: "PrtSc" },
];
