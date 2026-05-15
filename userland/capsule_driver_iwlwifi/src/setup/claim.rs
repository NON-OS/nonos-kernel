// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use nonos_libc::mk_device_claim;

pub fn claim(device_id: u64) -> Result<u64, &'static str> {
    let epoch = mk_device_claim(device_id);
    if epoch <= 0 {
        Err("iwlwifi: device claim failed")
    } else {
        Ok(epoch as u64)
    }
}
