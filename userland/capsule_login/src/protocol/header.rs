pub const MAGIC: u32 = 0x4E4C_474E;
pub const VERSION: u16 = 1;
pub const HDR_LEN: usize = 20;

#[derive(Clone, Copy)]
pub struct Request {
    pub op: u16,
    pub flags: u16,
    pub request_id: u32,
}
