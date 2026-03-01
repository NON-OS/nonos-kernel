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

#[derive(Clone, Copy, Debug, Default)]
pub struct CodecQuirks {
    pub power_delay: bool,
    pub toggle_eapd: bool,
    pub pin_sense_workaround: bool,
    pub gpio_setup: bool,
    pub gpio_mask: u8,
    pub gpio_data: u8,
    pub hp_sense_workaround: bool,
    pub inverted_mute: bool,
    pub needs_reset: bool,
    pub coef_quirk: bool,
    pub pin_config_override: bool,
    pub no_power_mgmt: bool,
    pub legacy_init: bool,
}

impl CodecQuirks {
    pub const fn empty() -> Self {
        Self {
            power_delay: false,
            toggle_eapd: false,
            pin_sense_workaround: false,
            gpio_setup: false,
            gpio_mask: 0,
            gpio_data: 0,
            hp_sense_workaround: false,
            inverted_mute: false,
            needs_reset: false,
            coef_quirk: false,
            pin_config_override: false,
            no_power_mgmt: false,
            legacy_init: false,
        }
    }

    pub fn has_quirks(&self) -> bool {
        self.power_delay || self.toggle_eapd || self.pin_sense_workaround ||
        self.gpio_setup || self.hp_sense_workaround || self.inverted_mute ||
        self.needs_reset || self.coef_quirk || self.pin_config_override ||
        self.no_power_mgmt || self.legacy_init
    }

    pub fn quirk_count(&self) -> usize {
        let mut count = 0;
        if self.power_delay { count += 1; }
        if self.toggle_eapd { count += 1; }
        if self.pin_sense_workaround { count += 1; }
        if self.gpio_setup { count += 1; }
        if self.hp_sense_workaround { count += 1; }
        if self.inverted_mute { count += 1; }
        if self.needs_reset { count += 1; }
        if self.coef_quirk { count += 1; }
        if self.pin_config_override { count += 1; }
        if self.no_power_mgmt { count += 1; }
        if self.legacy_init { count += 1; }
        count
    }
}

pub fn get_codec_quirks(vendor_id: u16, device_id: u16) -> CodecQuirks {
    match (vendor_id, device_id) {
        (0x10EC, 0x0269) | (0x10EC, 0x0275) | (0x10EC, 0x0276) => CodecQuirks {
            power_delay: true,
            toggle_eapd: true,
            gpio_setup: true,
            gpio_mask: 0x03,
            gpio_data: 0x03,
            hp_sense_workaround: true,
            ..CodecQuirks::empty()
        },
        (0x10EC, 0x0255) | (0x10EC, 0x0256) | (0x10EC, 0x0257) => CodecQuirks {
            power_delay: true,
            coef_quirk: true,
            hp_sense_workaround: true,
            ..CodecQuirks::empty()
        },
        (0x10EC, 0x0282) | (0x10EC, 0x0283) | (0x10EC, 0x0285) | (0x10EC, 0x0287) => CodecQuirks {
            power_delay: true,
            toggle_eapd: true,
            coef_quirk: true,
            ..CodecQuirks::empty()
        },
        (0x10EC, 0x0892) | (0x10EC, 0x0897) => CodecQuirks {
            gpio_setup: true,
            gpio_mask: 0x01,
            gpio_data: 0x01,
            ..CodecQuirks::empty()
        },
        (0x10EC, 0x1220) => CodecQuirks {
            power_delay: true,
            gpio_setup: true,
            gpio_mask: 0x03,
            gpio_data: 0x03,
            ..CodecQuirks::empty()
        },
        (0x8086, _) => CodecQuirks {
            no_power_mgmt: true,
            legacy_init: true,
            ..CodecQuirks::empty()
        },
        (0x10DE, _) => CodecQuirks {
            no_power_mgmt: true,
            legacy_init: true,
            ..CodecQuirks::empty()
        },
        (0x1002, _) => CodecQuirks {
            no_power_mgmt: true,
            ..CodecQuirks::empty()
        },
        (0x1AF4, _) | (0x15AD, _) => CodecQuirks::empty(),
        _ => CodecQuirks::empty(),
    }
}
