use crate::constants::*;
use crate::driver::Driver;
use crate::transaction::{control, valid_lengths, TransferError, TransferRequest, TransferResult};

pub fn transfer(driver: &Driver, req: TransferRequest<'_>) -> Result<TransferResult, TransferError> {
    if req.addr > 0x7F || !valid_lengths(req.write.len(), req.read_len) {
        return Err(TransferError::Invalid);
    }
    let regs = driver.regs;
    control::wait_idle(regs)?;
    control::set_target(regs, req.addr)?;
    control::enable(regs)?;
    let result = run(regs, req);
    let _ = control::disable(regs);
    result
}

pub fn probe(driver: &Driver, addr: u8) -> Result<bool, TransferError> {
    let req = TransferRequest { addr, write: &[], read_len: 1 };
    match transfer(driver, req) {
        Ok(_) => Ok(true),
        Err(TransferError::Nack) => Ok(false),
        Err(e) => Err(e),
    }
}

fn run(regs: crate::regs::Regs, req: TransferRequest<'_>) -> Result<TransferResult, TransferError> {
    let mut out = TransferResult::empty();
    let total = req.write.len() + req.read_len;
    let (mut wi, mut ri, mut ci) = (0usize, 0usize, 0usize);
    for _ in 0..TIMEOUT_ITERS {
        check_abort(regs, &mut out)?;
        drain_rx(regs, &mut out, &mut ri, req.read_len);
        while ci < total && tx_space(regs) > 0 && rx_space(regs) > 0 {
            let last = ci == total - 1;
            let mut cmd = if ci < req.write.len() { take_write(req.write, &mut wi) } else { IC_DATA_CMD_READ };
            if last {
                cmd |= IC_DATA_CMD_STOP;
            }
            regs.write32(IC_DATA_CMD, cmd);
            ci += 1;
        }
        if ci >= total && ri >= req.read_len && done(regs) {
            out.read_len = ri;
            return Ok(out);
        }
        core::hint::spin_loop();
    }
    Err(TransferError::Timeout)
}

fn check_abort(regs: crate::regs::Regs, out: &mut TransferResult) -> Result<(), TransferError> {
    if regs.read32(IC_RAW_INTR_STAT) & IC_INTR_TX_ABRT == 0 {
        return Ok(());
    }
    out.abort_source = regs.read32(IC_TX_ABRT_SOURCE);
    let _ = regs.read32(IC_CLR_TX_ABRT);
    Err(TransferError::Nack)
}

fn drain_rx(regs: crate::regs::Regs, out: &mut TransferResult, ri: &mut usize, read_len: usize) {
    while *ri < read_len && regs.read32(IC_STATUS) & IC_STATUS_RFNE != 0 {
        out.read[*ri] = (regs.read32(IC_DATA_CMD) & 0xFF) as u8;
        *ri += 1;
    }
}

fn tx_space(regs: crate::regs::Regs) -> u32 {
    TX_FIFO_DEPTH.saturating_sub(regs.read32(IC_TXFLR))
}

fn rx_space(regs: crate::regs::Regs) -> u32 {
    RX_FIFO_DEPTH.saturating_sub(regs.read32(IC_RXFLR))
}

fn take_write(write: &[u8], wi: &mut usize) -> u32 {
    let v = write[*wi] as u32;
    *wi += 1;
    v
}

fn done(regs: crate::regs::Regs) -> bool {
    let status = regs.read32(IC_STATUS);
    status & IC_STATUS_TFE != 0 && status & IC_STATUS_MST_ACTIVITY == 0
}
