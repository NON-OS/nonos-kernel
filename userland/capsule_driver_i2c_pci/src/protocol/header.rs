pub const MAGIC: u32 = 0x4E49_3243;
pub const VERSION: u16 = 1;
pub const HDR_LEN: usize = 20;

#[derive(Clone, Copy)]
pub struct Request {
    pub op: u16,
    pub request_id: u64,
}
