use crate::driver::Driver;
use crate::firmware::FirmwareStageState;
use crate::protocol::{E_FW_INVALID, E_OK, Request};
use crate::server::respond;

pub fn handle(driver: &mut Driver, sender_pid: u32, req: &Request, out: &mut [u8]) {
    match driver.stage_firmware() {
        Some(state) => reply(sender_pid, req, state, out),
        None => {
            let _ = respond::send(sender_pid, req, E_FW_INVALID, &[], out);
        }
    }
}

fn reply(sender_pid: u32, req: &Request, state: FirmwareStageState, out: &mut [u8]) {
    let mut body = [0u8; 32];
    body[0..2].copy_from_slice(&state.major.to_le_bytes());
    body[2..4].copy_from_slice(&state.minor.to_le_bytes());
    body[4..6].copy_from_slice(&state.api.to_le_bytes());
    body[8..12].copy_from_slice(&state.build.to_le_bytes());
    body[12..14].copy_from_slice(&state.init_sections.to_le_bytes());
    body[14..16].copy_from_slice(&state.runtime_sections.to_le_bytes());
    body[16..18].copy_from_slice(&state.paging_sections.to_le_bytes());
    body[20..24].copy_from_slice(&state.staged_bytes.to_le_bytes());
    let _ = respond::send(sender_pid, req, E_OK, &body, out);
}

