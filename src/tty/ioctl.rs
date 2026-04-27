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

use super::driver::TtyStruct;
use super::termios::{Termios, Winsize};
use crate::usercopy::{read_user_value, write_user_value};

pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCSCTTY: u32 = 0x540E;
pub const TIOCNOTTY: u32 = 0x5422;
pub const TIOCOUTQ: u32 = 0x5411;
pub const TIOCINQ: u32 = 0x541B;
pub const TCFLSH: u32 = 0x540B;
pub const TCSBRK: u32 = 0x5409;
pub const TIOCSTI: u32 = 0x5412;

pub fn tty_ioctl(tty: &mut TtyStruct, cmd: u32, arg: u64) -> Result<i64, i32> {
    match cmd {
        TCGETS => {
            write_user_value(arg, &tty.termios).map_err(|e| i32::from(e))?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let new_termios: Termios = read_user_value(arg).map_err(|e| i32::from(e))?;
            let old = tty.termios;
            tty.termios = new_termios;
            if cmd == TCSETSF {
                let ldisc = tty.ldisc.clone();
                ldisc.flush_buffer(tty);
            }
            tty.driver.ops.set_termios(tty, &old)?;
            Ok(0)
        }
        TIOCGWINSZ => {
            write_user_value(arg, &tty.winsize).map_err(|e| i32::from(e))?;
            Ok(0)
        }
        TIOCSWINSZ => {
            let new_winsize: Winsize = read_user_value(arg).map_err(|e| i32::from(e))?;
            tty.winsize = new_winsize;
            Ok(0)
        }
        TIOCGPGRP => {
            let pgrp = crate::process::get_tty_pgrp(tty.index).ok_or(-3)?;
            write_user_value(arg, &pgrp).map_err(|e| i32::from(e))?;
            Ok(0)
        }
        TIOCSPGRP => {
            let pgrp: i32 = read_user_value(arg).map_err(|e| i32::from(e))?;
            crate::process::set_tty_pgrp(tty.index, pgrp)?;
            Ok(0)
        }
        TIOCSCTTY => {
            crate::process::set_controlling_tty(tty.index, arg as u32)?;
            Ok(0)
        }
        TIOCNOTTY => {
            crate::process::release_controlling_tty(crate::process::current_pid().unwrap_or(1))?;
            Ok(0)
        }
        TIOCOUTQ => Ok(tty.driver.ops.chars_in_buffer(tty) as i64),
        TCFLSH => {
            let ldisc = tty.ldisc.clone();
            ldisc.flush_buffer(tty);
            Ok(0)
        }
        _ => {
            let ldisc = tty.ldisc.clone();
            ldisc.ioctl(tty, cmd, arg)
        }
    }
}
