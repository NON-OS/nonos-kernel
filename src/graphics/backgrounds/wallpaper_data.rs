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

pub(super) static WALLPAPER_NETWORK_1: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-1.png");
pub(super) static WALLPAPER_NETWORK_2: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-2.png");
pub(super) static WALLPAPER_NETWORK_3: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-3.png");
pub(super) static WALLPAPER_NETWORK_4: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-4.png");
pub(super) static WALLPAPER_NETWORK_5: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-5.png");
pub(super) static WALLPAPER_NETWORK_6: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-6.png");
pub(super) static WALLPAPER_NETWORK_7: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-7.png");
pub(super) static WALLPAPER_NETWORK_8: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-8.png");
pub(super) static WALLPAPER_NETWORK_9: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-9.png");
pub(super) static WALLPAPER_NETWORK_10: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-10.png");
pub(super) static WALLPAPER_NETWORK_11: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-11.png");

pub(super) static WALLPAPER_FIELD_1: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-1.png");
pub(super) static WALLPAPER_FIELD_2: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-2.png");
pub(super) static WALLPAPER_FIELD_3: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-3.png");
pub(super) static WALLPAPER_FIELD_4: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-4.png");
pub(super) static WALLPAPER_FIELD_5: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-5.png");

pub(super) static WALLPAPER_HARDWARE_1: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-1.png");
pub(super) static WALLPAPER_HARDWARE_2: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-2.png");
pub(super) static WALLPAPER_HARDWARE_3: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-3.png");
pub(super) static WALLPAPER_HARDWARE_4: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-4.png");
pub(super) static WALLPAPER_HARDWARE_5: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-5.png");
pub(super) static WALLPAPER_HARDWARE_6: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-6.png");
pub(super) static WALLPAPER_HARDWARE_7: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-7.png");

pub(super) static WALLPAPER_SPECIAL_1A: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-1a.png");
pub(super) static WALLPAPER_SPECIAL_1B: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-1b.png");
pub(super) static WALLPAPER_SPECIAL_2A: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-2a.png");
pub(super) static WALLPAPER_SPECIAL_2B: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-2b.png");
pub(super) static WALLPAPER_SPECIAL_3: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-3.png");
pub(super) static WALLPAPER_SPECIAL_4: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-4.png");
pub(super) static WALLPAPER_SPECIAL_5: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-5.png");
pub(super) static WALLPAPER_SPECIAL_6: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-6.png");
pub(super) static WALLPAPER_SPECIAL_7: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-7.png");
pub(super) static WALLPAPER_SPECIAL_8: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-8.png");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WallpaperCategory {
    NetworkTopology = 0,
    FieldFocus = 1,
    HardwareAesthetic = 2,
    SpecialVariants = 3,
}

impl WallpaperCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::NetworkTopology => "Network Topology",
            Self::FieldFocus => "Field + Focus",
            Self::HardwareAesthetic => "Hardware Aesthetic",
            Self::SpecialVariants => "Special Variants",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Self::NetworkTopology => "Network",
            Self::FieldFocus => "Field",
            Self::HardwareAesthetic => "Hardware",
            Self::SpecialVariants => "Special",
        }
    }

    pub fn all() -> &'static [WallpaperCategory] {
        &[Self::NetworkTopology, Self::FieldFocus, Self::HardwareAesthetic, Self::SpecialVariants]
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NetworkTopology,
            1 => Self::FieldFocus,
            2 => Self::HardwareAesthetic,
            3 => Self::SpecialVariants,
            _ => Self::NetworkTopology,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WallpaperInfo {
    pub id: u8,
    pub category: WallpaperCategory,
    pub name: &'static str,
    pub filename: &'static str,
}

pub const WALLPAPERS: &[WallpaperInfo] = &[
    WallpaperInfo { id: 0, category: WallpaperCategory::NetworkTopology, name: "Network 1", filename: "network-topology-1.png" },
    WallpaperInfo { id: 1, category: WallpaperCategory::NetworkTopology, name: "Network 2", filename: "network-topology-2.png" },
    WallpaperInfo { id: 2, category: WallpaperCategory::NetworkTopology, name: "Network 3", filename: "network-topology-3.png" },
    WallpaperInfo { id: 3, category: WallpaperCategory::NetworkTopology, name: "Network 4", filename: "network-topology-4.png" },
    WallpaperInfo { id: 4, category: WallpaperCategory::NetworkTopology, name: "Network 5", filename: "network-topology-5.png" },
    WallpaperInfo { id: 5, category: WallpaperCategory::NetworkTopology, name: "Network 6", filename: "network-topology-6.png" },
    WallpaperInfo { id: 6, category: WallpaperCategory::NetworkTopology, name: "Network 7", filename: "network-topology-7.png" },
    WallpaperInfo { id: 7, category: WallpaperCategory::NetworkTopology, name: "Network 8", filename: "network-topology-8.png" },
    WallpaperInfo { id: 8, category: WallpaperCategory::NetworkTopology, name: "Network 9", filename: "network-topology-9.png" },
    WallpaperInfo { id: 9, category: WallpaperCategory::NetworkTopology, name: "Network 10", filename: "network-topology-10.png" },
    WallpaperInfo { id: 10, category: WallpaperCategory::NetworkTopology, name: "Network 11", filename: "network-topology-11.png" },
    WallpaperInfo { id: 11, category: WallpaperCategory::FieldFocus, name: "Field 1", filename: "field-focus-1.png" },
    WallpaperInfo { id: 12, category: WallpaperCategory::FieldFocus, name: "Field 2", filename: "field-focus-2.png" },
    WallpaperInfo { id: 13, category: WallpaperCategory::FieldFocus, name: "Field 3", filename: "field-focus-3.png" },
    WallpaperInfo { id: 14, category: WallpaperCategory::FieldFocus, name: "Field 4", filename: "field-focus-4.png" },
    WallpaperInfo { id: 15, category: WallpaperCategory::FieldFocus, name: "Field 5", filename: "field-focus-5.png" },
    WallpaperInfo { id: 16, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 1", filename: "hardware-aesthetic-1.png" },
    WallpaperInfo { id: 17, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 2", filename: "hardware-aesthetic-2.png" },
    WallpaperInfo { id: 18, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 3", filename: "hardware-aesthetic-3.png" },
    WallpaperInfo { id: 19, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 4", filename: "hardware-aesthetic-4.png" },
    WallpaperInfo { id: 20, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 5", filename: "hardware-aesthetic-5.png" },
    WallpaperInfo { id: 21, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 6", filename: "hardware-aesthetic-6.png" },
    WallpaperInfo { id: 22, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 7", filename: "hardware-aesthetic-7.png" },
    WallpaperInfo { id: 23, category: WallpaperCategory::SpecialVariants, name: "Special 1A", filename: "special-variant-1a.png" },
    WallpaperInfo { id: 24, category: WallpaperCategory::SpecialVariants, name: "Special 1B", filename: "special-variant-1b.png" },
    WallpaperInfo { id: 25, category: WallpaperCategory::SpecialVariants, name: "Special 2A", filename: "special-variant-2a.png" },
    WallpaperInfo { id: 26, category: WallpaperCategory::SpecialVariants, name: "Special 2B", filename: "special-variant-2b.png" },
    WallpaperInfo { id: 27, category: WallpaperCategory::SpecialVariants, name: "Special 3", filename: "special-variant-3.png" },
    WallpaperInfo { id: 28, category: WallpaperCategory::SpecialVariants, name: "Special 4", filename: "special-variant-4.png" },
    WallpaperInfo { id: 29, category: WallpaperCategory::SpecialVariants, name: "Special 5", filename: "special-variant-5.png" },
    WallpaperInfo { id: 30, category: WallpaperCategory::SpecialVariants, name: "Special 6", filename: "special-variant-6.png" },
    WallpaperInfo { id: 31, category: WallpaperCategory::SpecialVariants, name: "Special 7", filename: "special-variant-7.png" },
    WallpaperInfo { id: 32, category: WallpaperCategory::SpecialVariants, name: "Special 8", filename: "special-variant-8.png" },
];

pub const WALLPAPER_COUNT: usize = 33;
pub const DEFAULT_WALLPAPER_ID: u8 = 30;

pub(super) fn get_embedded_wallpaper_data(id: u8) -> Option<&'static [u8]> {
    match id {
        0 => Some(WALLPAPER_NETWORK_1),
        1 => Some(WALLPAPER_NETWORK_2),
        2 => Some(WALLPAPER_NETWORK_3),
        3 => Some(WALLPAPER_NETWORK_4),
        4 => Some(WALLPAPER_NETWORK_5),
        5 => Some(WALLPAPER_NETWORK_6),
        6 => Some(WALLPAPER_NETWORK_7),
        7 => Some(WALLPAPER_NETWORK_8),
        8 => Some(WALLPAPER_NETWORK_9),
        9 => Some(WALLPAPER_NETWORK_10),
        10 => Some(WALLPAPER_NETWORK_11),
        11 => Some(WALLPAPER_FIELD_1),
        12 => Some(WALLPAPER_FIELD_2),
        13 => Some(WALLPAPER_FIELD_3),
        14 => Some(WALLPAPER_FIELD_4),
        15 => Some(WALLPAPER_FIELD_5),
        16 => Some(WALLPAPER_HARDWARE_1),
        17 => Some(WALLPAPER_HARDWARE_2),
        18 => Some(WALLPAPER_HARDWARE_3),
        19 => Some(WALLPAPER_HARDWARE_4),
        20 => Some(WALLPAPER_HARDWARE_5),
        21 => Some(WALLPAPER_HARDWARE_6),
        22 => Some(WALLPAPER_HARDWARE_7),
        23 => Some(WALLPAPER_SPECIAL_1A),
        24 => Some(WALLPAPER_SPECIAL_1B),
        25 => Some(WALLPAPER_SPECIAL_2A),
        26 => Some(WALLPAPER_SPECIAL_2B),
        27 => Some(WALLPAPER_SPECIAL_3),
        28 => Some(WALLPAPER_SPECIAL_4),
        29 => Some(WALLPAPER_SPECIAL_5),
        30 => Some(WALLPAPER_SPECIAL_6),
        31 => Some(WALLPAPER_SPECIAL_7),
        32 => Some(WALLPAPER_SPECIAL_8),
        _ => None,
    }
}

pub fn category_count(category: WallpaperCategory) -> usize {
    match category {
        WallpaperCategory::NetworkTopology => 11,
        WallpaperCategory::FieldFocus => 5,
        WallpaperCategory::HardwareAesthetic => 7,
        WallpaperCategory::SpecialVariants => 10,
    }
}
