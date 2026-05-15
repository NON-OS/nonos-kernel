pub struct State {
    pub i2c_port: u32,
    pub i2c_pid: u32,
    pub addr: u8,
    pub descriptor: [u8; 30],
    pub descriptor_len: usize,
    pub probes: u64,
}

impl State {
    pub const fn new(i2c_port: u32, i2c_pid: u32) -> Self {
        Self { i2c_port, i2c_pid, addr: 0, descriptor: [0; 30], descriptor_len: 0, probes: 0 }
    }

    pub fn found(&self) -> bool {
        self.descriptor_len != 0
    }
}

