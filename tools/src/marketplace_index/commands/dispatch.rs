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

use crate::args::Flags;
use crate::error::CliError;

use super::{encode, inspect, keygen, sign, verify};

pub fn dispatch(args: &[String]) -> Result<(), CliError> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };
    let flags = Flags::parse(rest).map_err(CliError::Json)?;
    match cmd {
        "encode" => encode::run(&flags),
        "sign" => sign::run(&flags),
        "verify" => verify::run(&flags),
        "inspect" => inspect::run(&flags),
        "keygen" => keygen::run(&flags),
        "" | "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(CliError::Json(format!("unknown subcommand: {other}"))),
    }
}

fn print_usage() {
    eprintln!(
        "usage: marketplace-index <subcommand> [flags]\n\n\
         subcommands:\n\
           encode    --in <json> --pubkey <hex32> --out <blob>\n\
           sign      --in <json> [--key-file <path>|--key-env <var>] --out <blob>\n\
                     [--pubkey <hex32>] [--json-out <path>] [--previous-serial N]\n\
           verify    --in <blob> --pubkey <hex32> [--previous-serial N]\n\
           inspect   --in <blob>\n\
           keygen    --out <seed-file>\n\n\
         operator seed sources: --key-file <path-with-32-byte-binary-seed>\n\
         or env NONOS_OPERATOR_SEED (32-byte hex). The CLI never\n\
         prints, copies, or otherwise emits private key material.\n"
    );
}
