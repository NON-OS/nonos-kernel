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

// Active wallpapers
pub(super) static WALLPAPER_NETWORK_13: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-13.png");
pub(super) static WALLPAPER_NETWORK_18: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-18.png");
pub(super) static WALLPAPER_FIELD_6: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-6.png");
pub(super) static WALLPAPER_FIELD_7: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-7.png");
pub(super) static WALLPAPER_HARDWARE_7: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-7.png");
pub(super) static WALLPAPER_SPECIAL_2B: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-2b.png");
pub(super) static WALLPAPER_SPECIAL_7: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-7.png");
pub(super) static WALLPAPER_SPECIAL_10: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-10.png");
pub(super) static WALLPAPER_SPECIAL_11: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-11.png");
pub(super) static WALLPAPER_SPECIAL_14: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-14.png");

// Inactive wallpapers (commented out to reduce binary size)
// pub(super) static WALLPAPER_NETWORK_1: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-1.png");
// pub(super) static WALLPAPER_NETWORK_2: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-2.png");
// pub(super) static WALLPAPER_NETWORK_3: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-3.png");
// pub(super) static WALLPAPER_NETWORK_4: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-4.png");
// pub(super) static WALLPAPER_NETWORK_5: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-5.png");
// pub(super) static WALLPAPER_NETWORK_6: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-6.png");
// pub(super) static WALLPAPER_NETWORK_7: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-7.png");
// pub(super) static WALLPAPER_NETWORK_8: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-8.png");
// pub(super) static WALLPAPER_NETWORK_9: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-9.png");
// pub(super) static WALLPAPER_NETWORK_10: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-10.png");
// pub(super) static WALLPAPER_NETWORK_11: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-11.png");
// pub(super) static WALLPAPER_NETWORK_14: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-14.png");
// pub(super) static WALLPAPER_NETWORK_15: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-15.png");
// pub(super) static WALLPAPER_NETWORK_16: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-16.png");
// pub(super) static WALLPAPER_NETWORK_17: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-17.png");
// pub(super) static WALLPAPER_NETWORK_19: &[u8] = include_bytes!("../../../assets/wallpapers/network-topology-19.png");
// pub(super) static WALLPAPER_FIELD_1: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-1.png");
// pub(super) static WALLPAPER_FIELD_2: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-2.png");
// pub(super) static WALLPAPER_FIELD_3: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-3.png");
// pub(super) static WALLPAPER_FIELD_4: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-4.png");
// pub(super) static WALLPAPER_FIELD_5: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-5.png");
// pub(super) static WALLPAPER_FIELD_8: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-8.png");
// pub(super) static WALLPAPER_FIELD_9: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-9.png");
// pub(super) static WALLPAPER_FIELD_10: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-10.png");
// pub(super) static WALLPAPER_FIELD_11: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-11.png");
// pub(super) static WALLPAPER_FIELD_12: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-12.png");
// pub(super) static WALLPAPER_FIELD_13: &[u8] = include_bytes!("../../../assets/wallpapers/field-focus-13.png");
// pub(super) static WALLPAPER_HARDWARE_1: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-1.png");
// pub(super) static WALLPAPER_HARDWARE_2: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-2.png");
// pub(super) static WALLPAPER_HARDWARE_3: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-3.png");
// pub(super) static WALLPAPER_HARDWARE_4: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-4.png");
// pub(super) static WALLPAPER_HARDWARE_5: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-5.png");
// pub(super) static WALLPAPER_HARDWARE_6: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-6.png");
// pub(super) static WALLPAPER_HARDWARE_8: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-8.png");
// pub(super) static WALLPAPER_HARDWARE_9: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-9.png");
// pub(super) static WALLPAPER_HARDWARE_10: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-10.png");
// pub(super) static WALLPAPER_HARDWARE_11: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-11.png");
// pub(super) static WALLPAPER_HARDWARE_12: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-12.png");
// pub(super) static WALLPAPER_HARDWARE_13: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-13.png");
// pub(super) static WALLPAPER_HARDWARE_14: &[u8] = include_bytes!("../../../assets/wallpapers/hardware-aesthetic-14.png");
// pub(super) static WALLPAPER_SPECIAL_1A: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-1a.png");
// pub(super) static WALLPAPER_SPECIAL_1B: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-1b.png");
// pub(super) static WALLPAPER_SPECIAL_2A: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-2a.png");
// pub(super) static WALLPAPER_SPECIAL_3: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-3.png");
// pub(super) static WALLPAPER_SPECIAL_4: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-4.png");
// pub(super) static WALLPAPER_SPECIAL_5: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-5.png");
// pub(super) static WALLPAPER_SPECIAL_6: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-6.png");
// pub(super) static WALLPAPER_SPECIAL_8: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-8.png");
// pub(super) static WALLPAPER_SPECIAL_9: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-9.png");
// pub(super) static WALLPAPER_SPECIAL_12: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-12.png");
// pub(super) static WALLPAPER_SPECIAL_13: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-13.png");
// pub(super) static WALLPAPER_SPECIAL_15: &[u8] = include_bytes!("../../../assets/wallpapers/special-variant-15.png");

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
    WallpaperInfo { id: 0, category: WallpaperCategory::NetworkTopology, name: "Network 18", filename: "network-topology-18.png" },
    WallpaperInfo { id: 1, category: WallpaperCategory::NetworkTopology, name: "Network 13", filename: "network-topology-13.png" },
    WallpaperInfo { id: 2, category: WallpaperCategory::FieldFocus, name: "Field 6", filename: "field-focus-6.png" },
    WallpaperInfo { id: 3, category: WallpaperCategory::FieldFocus, name: "Field 7", filename: "field-focus-7.png" },
    WallpaperInfo { id: 4, category: WallpaperCategory::HardwareAesthetic, name: "Hardware 7", filename: "hardware-aesthetic-7.png" },
    WallpaperInfo { id: 5, category: WallpaperCategory::SpecialVariants, name: "Special 2B", filename: "special-variant-2b.png" },
    WallpaperInfo { id: 6, category: WallpaperCategory::SpecialVariants, name: "Special 7", filename: "special-variant-7.png" },
    WallpaperInfo { id: 7, category: WallpaperCategory::SpecialVariants, name: "Special 10", filename: "special-variant-10.png" },
    WallpaperInfo { id: 8, category: WallpaperCategory::SpecialVariants, name: "Special 11", filename: "special-variant-11.png" },
    WallpaperInfo { id: 9, category: WallpaperCategory::SpecialVariants, name: "Special 14", filename: "special-variant-14.png" },
];

pub const WALLPAPER_COUNT: usize = 10;
pub const DEFAULT_WALLPAPER_ID: u8 = 9;

pub(super) fn get_embedded_wallpaper_data(id: u8) -> Option<&'static [u8]> {
    match id {
        0 => Some(WALLPAPER_NETWORK_18),
        1 => Some(WALLPAPER_NETWORK_13),
        2 => Some(WALLPAPER_FIELD_6),
        3 => Some(WALLPAPER_FIELD_7),
        4 => Some(WALLPAPER_HARDWARE_7),
        5 => Some(WALLPAPER_SPECIAL_2B),
        6 => Some(WALLPAPER_SPECIAL_7),
        7 => Some(WALLPAPER_SPECIAL_10),
        8 => Some(WALLPAPER_SPECIAL_11),
        9 => Some(WALLPAPER_SPECIAL_14),
        _ => None,
    }
}

pub fn category_count(category: WallpaperCategory) -> usize {
    match category {
        WallpaperCategory::NetworkTopology => 2,
        WallpaperCategory::FieldFocus => 2,
        WallpaperCategory::HardwareAesthetic => 1,
        WallpaperCategory::SpecialVariants => 5,
    }
}
