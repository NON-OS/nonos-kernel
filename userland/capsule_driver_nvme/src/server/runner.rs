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

use alloc::vec;

use nonos_libc::{mk_ipc_recv, mk_irq_ack, mk_irq_poll, IrqPollOut};

use crate::protocol::{
    decode_request, E_INVAL, HDR_LEN, OP_CONTROLLER_INFO, OP_HEALTHCHECK, OP_IDENTIFY_CONTROLLER,
    OP_IDENTIFY_NAMESPACE, OP_SMART_HEALTH, RESP_HDR_LEN, SERVICE_NAME, SMART_HEALTH_PAYLOAD_LEN,
};
use crate::server::{error, handlers};
use crate::setup::Driver;

const TX_LEN: usize = RESP_HDR_LEN + 4 + SMART_HEALTH_PAYLOAD_LEN;

pub fn run(driver: Driver) -> ! {
    let mut rx = vec![0u8; HDR_LEN];
    let mut tx = vec![0u8; TX_LEN];
    let mut last_irq_seq = 0u64;
    let _service_name = SERVICE_NAME;

    loop {
        poll_irq(&driver, &mut last_irq_seq);
        let n = mk_ipc_recv(0, rx.as_mut_ptr(), HDR_LEN, 0);
        if n <= 0 {
            continue;
        }
        let req = match decode_request(&rx[..n as usize]) {
            Some(r) => r,
            None => {
                error::reply_decode_failed(&mut tx, E_INVAL);
                continue;
            }
        };
        if req.payload_len != 0 {
            error::reply_with_status(&mut tx, &req, E_INVAL);
            continue;
        }
        match req.op {
            OP_HEALTHCHECK => handlers::health::handle(&req, &mut tx),
            OP_CONTROLLER_INFO => handlers::controller_info::handle(&driver, &req, &mut tx),
            OP_IDENTIFY_CONTROLLER => handlers::identify_controller::handle(&driver, &req, &mut tx),
            OP_IDENTIFY_NAMESPACE => handlers::identify_namespace::handle(&driver, &req, &mut tx),
            OP_SMART_HEALTH => handlers::smart_health::handle(&driver, &req, &mut tx),
            _ => error::reply_with_status(&mut tx, &req, E_INVAL),
        }
    }
}

fn poll_irq(driver: &Driver, last: &mut u64) {
    let mut irq = IrqPollOut { seq: 0, overflow: 0 };
    if mk_irq_poll(driver.handles.irq_grant_id(), &mut irq as *mut _) >= 0 && irq.seq != *last {
        *last = irq.seq;
        let _ = mk_irq_ack(driver.handles.irq_grant_id());
    }
}
