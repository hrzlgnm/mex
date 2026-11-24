// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

mod iface;
mod listener;
mod send;
mod transmit;
mod wire;

fn test_source() -> std::net::SocketAddr {
    "192.168.178.60:5353".parse().unwrap()
}

/// Records pin/send calls; fails the configured ones.
#[derive(Default)]
struct FakeSocket {
    calls: std::cell::RefCell<Vec<String>>,
    failing_pin: Option<Egress>,
    failing_send: std::cell::Cell<bool>,
}

impl QuerySocket for FakeSocket {
    fn pin(&self, egress: Egress) -> std::io::Result<()> {
        self.calls.borrow_mut().push(format!("pin {egress:?}"));
        if self.failing_pin == Some(egress) {
            return Err(std::io::ErrorKind::AddrNotAvailable.into());
        }
        Ok(())
    }

    fn send_to(&self, _bytes: &[u8], dest: SocketAddr) -> std::io::Result<()> {
        self.calls.borrow_mut().push(format!("send {dest}"));
        if self.failing_send.get() {
            return Err(std::io::ErrorKind::NetworkUnreachable.into());
        }
        Ok(())
    }
}

/// A wire sink whose every write fails, as a full or broken buffer
/// would: drives the encoders' error handling.
struct FailingSink;

impl std::io::Write for FailingSink {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WriteZero.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Seek for FailingSink {
    fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
        Ok(0)
    }
}

impl WireSink for FailingSink {
    fn into_bytes(self) -> Vec<u8> {
        Vec::new()
    }
}
