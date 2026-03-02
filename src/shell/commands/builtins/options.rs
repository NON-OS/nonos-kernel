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

use core::sync::atomic::{AtomicBool, Ordering};
use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW};
use crate::shell::commands::utils::{trim_bytes, starts_with};

static OPT_ERREXIT: AtomicBool = AtomicBool::new(false);
static OPT_NOUNSET: AtomicBool = AtomicBool::new(false);
static OPT_XTRACE: AtomicBool = AtomicBool::new(false);
static OPT_VERBOSE: AtomicBool = AtomicBool::new(false);
static OPT_NOCLOBBER: AtomicBool = AtomicBool::new(false);
static OPT_IGNOREEOF: AtomicBool = AtomicBool::new(true);

pub fn get_errexit() -> bool {
    OPT_ERREXIT.load(Ordering::Relaxed)
}

pub fn get_nounset() -> bool {
    OPT_NOUNSET.load(Ordering::Relaxed)
}

pub fn get_xtrace() -> bool {
    OPT_XTRACE.load(Ordering::Relaxed)
}

pub fn cmd_set(cmd: &[u8]) {
    let args = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        b"" as &[u8]
    };

    if args.is_empty() {
        print_line(b"Shell Options:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);

        let errexit = OPT_ERREXIT.load(Ordering::Relaxed);
        let nounset = OPT_NOUNSET.load(Ordering::Relaxed);
        let xtrace = OPT_XTRACE.load(Ordering::Relaxed);
        let verbose = OPT_VERBOSE.load(Ordering::Relaxed);
        let noclobber = OPT_NOCLOBBER.load(Ordering::Relaxed);
        let ignoreeof = OPT_IGNOREEOF.load(Ordering::Relaxed);

        print_line(if errexit { b"errexit     on    (exit on error)" } else { b"errexit     off   (exit on error)" },
            if errexit { COLOR_GREEN } else { COLOR_TEXT });
        print_line(if nounset { b"nounset     on    (error on unset vars)" } else { b"nounset     off   (error on unset vars)" },
            if nounset { COLOR_GREEN } else { COLOR_TEXT });
        print_line(if xtrace { b"xtrace      on    (debug tracing)" } else { b"xtrace      off   (debug tracing)" },
            if xtrace { COLOR_GREEN } else { COLOR_TEXT });
        print_line(if verbose { b"verbose     on    (verbose output)" } else { b"verbose     off   (verbose output)" },
            if verbose { COLOR_GREEN } else { COLOR_TEXT });
        print_line(if noclobber { b"noclobber   on    (no file overwrite)" } else { b"noclobber   off   (no file overwrite)" },
            if noclobber { COLOR_GREEN } else { COLOR_TEXT });
        print_line(if ignoreeof { b"ignoreeof   on    (ignore Ctrl-D)" } else { b"ignoreeof   off   (ignore Ctrl-D)" },
            if ignoreeof { COLOR_GREEN } else { COLOR_TEXT });
        return;
    }

    if starts_with(args, b"-o ") {
        let opt = trim_bytes(&args[3..]);
        set_option(opt, true);
    } else if starts_with(args, b"+o ") {
        let opt = trim_bytes(&args[3..]);
        set_option(opt, false);
    } else if starts_with(args, b"-e") {
        OPT_ERREXIT.store(true, Ordering::Relaxed);
        print_line(b"set: errexit enabled", COLOR_GREEN);
    } else if starts_with(args, b"+e") {
        OPT_ERREXIT.store(false, Ordering::Relaxed);
        print_line(b"set: errexit disabled", COLOR_TEXT);
    } else if starts_with(args, b"-u") {
        OPT_NOUNSET.store(true, Ordering::Relaxed);
        print_line(b"set: nounset enabled", COLOR_GREEN);
    } else if starts_with(args, b"+u") {
        OPT_NOUNSET.store(false, Ordering::Relaxed);
        print_line(b"set: nounset disabled", COLOR_TEXT);
    } else if starts_with(args, b"-x") {
        OPT_XTRACE.store(true, Ordering::Relaxed);
        print_line(b"set: xtrace enabled", COLOR_GREEN);
    } else if starts_with(args, b"+x") {
        OPT_XTRACE.store(false, Ordering::Relaxed);
        print_line(b"set: xtrace disabled", COLOR_TEXT);
    } else if starts_with(args, b"-v") {
        OPT_VERBOSE.store(true, Ordering::Relaxed);
        print_line(b"set: verbose enabled", COLOR_GREEN);
    } else if starts_with(args, b"+v") {
        OPT_VERBOSE.store(false, Ordering::Relaxed);
        print_line(b"set: verbose disabled", COLOR_TEXT);
    } else {
        print_line(b"Usage: set [-o option] or set -e/-u/-x/-v", COLOR_TEXT_DIM);
        print_line(b"  -o errexit    Exit on command failure", COLOR_TEXT_DIM);
        print_line(b"  -o nounset    Error on unset variables", COLOR_TEXT_DIM);
        print_line(b"  -o xtrace     Print commands before exec", COLOR_TEXT_DIM);
        print_line(b"  -o verbose    Verbose output", COLOR_TEXT_DIM);
        print_line(b"  -o noclobber  Prevent file overwrite", COLOR_TEXT_DIM);
        print_line(b"Use +o to disable options", COLOR_TEXT_DIM);
    }
}

fn set_option(name: &[u8], enable: bool) {
    match name {
        b"errexit" => {
            OPT_ERREXIT.store(enable, Ordering::Relaxed);
            print_line(if enable { b"set: errexit enabled" } else { b"set: errexit disabled" },
                if enable { COLOR_GREEN } else { COLOR_TEXT });
        }
        b"nounset" => {
            OPT_NOUNSET.store(enable, Ordering::Relaxed);
            print_line(if enable { b"set: nounset enabled" } else { b"set: nounset disabled" },
                if enable { COLOR_GREEN } else { COLOR_TEXT });
        }
        b"xtrace" => {
            OPT_XTRACE.store(enable, Ordering::Relaxed);
            print_line(if enable { b"set: xtrace enabled" } else { b"set: xtrace disabled" },
                if enable { COLOR_GREEN } else { COLOR_TEXT });
        }
        b"verbose" => {
            OPT_VERBOSE.store(enable, Ordering::Relaxed);
            print_line(if enable { b"set: verbose enabled" } else { b"set: verbose disabled" },
                if enable { COLOR_GREEN } else { COLOR_TEXT });
        }
        b"noclobber" => {
            OPT_NOCLOBBER.store(enable, Ordering::Relaxed);
            print_line(if enable { b"set: noclobber enabled" } else { b"set: noclobber disabled" },
                if enable { COLOR_GREEN } else { COLOR_TEXT });
        }
        b"ignoreeof" => {
            OPT_IGNOREEOF.store(enable, Ordering::Relaxed);
            print_line(if enable { b"set: ignoreeof enabled" } else { b"set: ignoreeof disabled" },
                if enable { COLOR_GREEN } else { COLOR_TEXT });
        }
        _ => {
            print_line(b"set: unknown option", COLOR_YELLOW);
        }
    }
}
