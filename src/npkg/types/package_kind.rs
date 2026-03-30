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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PackageKind {
    #[default]
    Binary,
    Library,
    Data,
    Font,
    Theme,
    Driver,
    Service,
    Meta,
}

impl PackageKind {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "binary" | "bin" => Some(Self::Binary),
            "library" | "lib" => Some(Self::Library),
            "data" => Some(Self::Data),
            "font" => Some(Self::Font),
            "theme" => Some(Self::Theme),
            "driver" => Some(Self::Driver),
            "service" => Some(Self::Service),
            "meta" => Some(Self::Meta),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Library => "library",
            Self::Data => "data",
            Self::Font => "font",
            Self::Theme => "theme",
            Self::Driver => "driver",
            Self::Service => "service",
            Self::Meta => "meta",
        }
    }
}
