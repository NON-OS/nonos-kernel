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

extern crate alloc;

use super::framework::{TestCase, TestResult, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("IPC");

    suite.add(TestCase::new("message_construction", test_message_construction, "ipc"));
    suite.add(TestCase::new("message_types", test_message_types, "ipc"));
    suite.add(TestCase::new("channel_creation", test_channel_creation, "ipc"));
    suite.add(TestCase::new("channel_send_receive", test_channel_send_receive, "ipc"));
    suite.add(TestCase::new("pipe_operations", test_pipe_operations, "ipc"));
    suite.add(TestCase::new("inbox_operations", test_inbox_operations, "ipc"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

pub(crate) fn test_message_construction() -> TestResult {
    use crate::ipc::message::{Message, MessageType};

    let msg = Message::new(1, 2, MessageType::Request, b"hello");

    if msg.sender() != 1 {
        return TestResult::Fail;
    }
    if msg.receiver() != 2 {
        return TestResult::Fail;
    }
    if msg.msg_type() != MessageType::Request {
        return TestResult::Fail;
    }
    if msg.payload() != b"hello" {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_message_types() -> TestResult {
    use crate::ipc::message::MessageType;

    let request = MessageType::Request;
    let response = MessageType::Response;
    let notification = MessageType::Notification;

    if request == response {
        return TestResult::Fail;
    }
    if response == notification {
        return TestResult::Fail;
    }
    if notification == request {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_channel_creation() -> TestResult {
    use crate::ipc::channel::{create_channel, destroy_channel};

    let channel_id = create_channel(1, 2);
    if channel_id == 0 {
        return TestResult::Fail;
    }

    let channel_id2 = create_channel(1, 3);
    if channel_id2 == 0 {
        return TestResult::Fail;
    }
    if channel_id == channel_id2 {
        return TestResult::Fail;
    }

    destroy_channel(channel_id);
    destroy_channel(channel_id2);

    TestResult::Pass
}

pub(crate) fn test_channel_send_receive() -> TestResult {
    use crate::ipc::channel::{create_channel, destroy_channel, receive, send};
    use crate::ipc::message::{Message, MessageType};

    let channel_id = create_channel(100, 101);

    let msg = Message::new(100, 101, MessageType::Request, b"test data");
    let sent = send(channel_id, msg);
    if !sent {
        return TestResult::Fail;
    }

    let received = receive(channel_id, 101);
    if received.is_none() {
        return TestResult::Fail;
    }

    let recv_msg = received.unwrap();
    if recv_msg.payload() != b"test data" {
        return TestResult::Fail;
    }

    destroy_channel(channel_id);

    TestResult::Pass
}

pub(crate) fn test_pipe_operations() -> TestResult {
    use crate::ipc::pipe::{close_pipe, create_pipe, pipe_read, pipe_write};

    let (read_end, write_end) = create_pipe();
    if read_end < 0 || write_end < 0 {
        return TestResult::Fail;
    }

    let data = b"pipe test";
    let written = pipe_write(write_end, data);
    if written != data.len() as isize {
        return TestResult::Fail;
    }

    let mut buf = [0u8; 32];
    let read = pipe_read(read_end, &mut buf);
    if read != data.len() as isize {
        return TestResult::Fail;
    }
    if &buf[..data.len()] != data {
        return TestResult::Fail;
    }

    close_pipe(read_end);
    close_pipe(write_end);

    TestResult::Pass
}

pub(crate) fn test_inbox_operations() -> TestResult {
    use crate::ipc::inbox::{check_inbox, clear_inbox, create_inbox, post_message};
    use crate::ipc::message::{Message, MessageType};

    let inbox_id = create_inbox(200);
    if inbox_id == 0 {
        return TestResult::Fail;
    }

    let msg = Message::new(1, 200, MessageType::Notification, b"notification");
    let posted = post_message(inbox_id, msg);
    if !posted {
        return TestResult::Fail;
    }

    let count = check_inbox(inbox_id);
    if count < 1 {
        return TestResult::Fail;
    }

    clear_inbox(inbox_id);
    let count_after = check_inbox(inbox_id);
    if count_after != 0 {
        return TestResult::Fail;
    }

    TestResult::Pass
}
