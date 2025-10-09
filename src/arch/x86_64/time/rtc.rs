//! Real Time Clock (RTC) Support for x86_64

#[derive(Debug, Clone, Copy)]
pub struct RtcTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Read a single RTC register (from CMOS)
fn rtc_read_reg(reg: u8) -> u8 {
    unsafe {
        // Disable NMI (bit 7 set) to avoid spurious interrupts during CMOS access
        crate::arch::x86_64::port::outb(0x70, reg | 0x80);
        crate::arch::x86_64::port::inb(0x71)
    }
}

/// Convert BCD to binary
fn bcd_to_bin(val: u8) -> u8 {
    ((val & 0xF0) >> 4) * 10 + (val & 0x0F)
}

/// Read full RTC time
pub fn read_rtc() -> RtcTime {
    // Wait until RTC is not updating (bit 7 of register 0x0A clear)
    while rtc_read_reg(0x0A) & 0x80 != 0 {}

    let second = rtc_read_reg(0x00);
    let minute = rtc_read_reg(0x02);
    let hour   = rtc_read_reg(0x04);
    let day    = rtc_read_reg(0x07);
    let month  = rtc_read_reg(0x08);
    let year   = rtc_read_reg(0x09);
    let century = rtc_read_reg(0x32); // Optional, not all BIOSes expose this

    // Check if RTC is in BCD mode (register 0x0B bit 2 clear)
    let is_bcd = rtc_read_reg(0x0B) & 0x04 == 0;

    let sec = if is_bcd { bcd_to_bin(second) } else { second };
    let min = if is_bcd { bcd_to_bin(minute) } else { minute };
    let hr  = if is_bcd { bcd_to_bin(hour)   } else { hour   };
    let dy  = if is_bcd { bcd_to_bin(day)    } else { day    };
    let mn  = if is_bcd { bcd_to_bin(month)  } else { month  };
    let yr  = if is_bcd { bcd_to_bin(year)   } else { year   };
    let cent = if is_bcd { bcd_to_bin(century) } else { century };

    // Compute full year (handles 19xx/20xx split)
    let full_year = if cent != 0 {
        (cent as u16) * 100 + (yr as u16)
    } else if yr < 70 {
        2000 + (yr as u16)
    } else {
        1900 + (yr as u16)
    };

    RtcTime {
        year: full_year,
        month: mn,
        day: dy,
        hour: hr,
        minute: min,
        second: sec,
    }
}
