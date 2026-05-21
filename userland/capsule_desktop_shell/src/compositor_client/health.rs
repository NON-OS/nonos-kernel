use super::wire::call;

const OP: u16 = 0x0001;

pub fn healthcheck(compositor_port: u32, request_id: u32) -> Result<(), &'static str> {
    let status = call(compositor_port, OP, request_id, &[])?;
    if status != 0 {
        return Err("compositor health rejected");
    }
    Ok(())
}
