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

/// A site the start page offers before anything is bookmarked.
pub struct Shortcut {
    pub label: &'static str,
    pub url: &'static str,
}

pub const SHORTCUTS: [Shortcut; 4] = [
    Shortcut { label: "neverssl.com", url: "http://neverssl.com/" },
    Shortcut { label: "example.com", url: "http://example.com/" },
    Shortcut { label: "info.cern.ch", url: "http://info.cern.ch/" },
    Shortcut { label: "httpforever.com", url: "http://httpforever.com/" },
];
