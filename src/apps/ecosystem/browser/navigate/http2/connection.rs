extern crate alloc;
use super::stream::Stream;
use alloc::collections::BTreeMap;

pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub struct Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Settings {
    pub fn default_settings() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: 100,
            initial_window_size: 65535,
            max_frame_size: 16384,
            max_header_list_size: 8192,
        }
    }

    pub fn apply(&mut self, id: u16, value: u32) {
        match id {
            1 => self.header_table_size = value,
            2 => self.enable_push = value != 0,
            3 => self.max_concurrent_streams = value,
            4 => self.initial_window_size = value,
            5 => self.max_frame_size = value,
            6 => self.max_header_list_size = value,
            _ => {}
        }
    }
}

pub struct Connection {
    pub local_settings: Settings,
    pub remote_settings: Settings,
    pub streams: BTreeMap<u32, Stream>,
    pub next_stream_id: u32,
    pub connection_window: i32,
}

impl Connection {
    pub fn new() -> Self {
        Self {
            local_settings: Settings::default_settings(),
            remote_settings: Settings::default_settings(),
            streams: BTreeMap::new(),
            next_stream_id: 1,
            connection_window: 65535,
        }
    }

    pub fn new_stream(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        let window = self.remote_settings.initial_window_size as i32;
        let mut stream = Stream::new(id, window);
        stream.open();
        self.streams.insert(id, stream);
        id
    }

    pub fn get_stream(&self, id: u32) -> Option<&Stream> {
        self.streams.get(&id)
    }
    pub fn get_stream_mut(&mut self, id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }
}
