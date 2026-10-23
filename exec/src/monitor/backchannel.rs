/// This backchannel uses rkyv instead of sudo-rs implementation because I don't want to maintain a custom serialization format
/// and rkyv is clearly suitable and performant. I think serde would be too long to setup for this use case.
use log::{trace, warn};
use rkyv::{Archive, Deserialize, Serialize};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

pub const MAX_BACKCHANNEL_MESSAGE_SIZE: usize = 64 * 1024;

/// A frame is the length of the message as a little-endian `u32`, then the message.
const FRAME_HEADER_SIZE: usize = size_of::<u32>();

macro_rules! signals {
    (core + [$($extra:expr),* $(,)?]) => {
        &[
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTSTP,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGCONT,
            libc::SIGALRM,
            $($extra),*
        ]
    };
}

/// Signals that can be forwarded from runner to command.
pub const FORWARDABLE_SIGNALS: &[libc::c_int] =
    signals!(core + [libc::SIGUSR1, libc::SIGUSR2, libc::SIGWINCH]);

/// Signals to register for no-pty execution (runner).
pub const RUNNER_SIGNALS_NO_PTY: &[libc::c_int] = signals!(
    core + [
        libc::SIGPIPE,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGCHLD,
        libc::SIGWINCH
    ]
);

/// Signals to register for pty execution (runner).
pub const RUNNER_SIGNALS_WITH_PTY: &[libc::c_int] =
    signals!(core + [libc::SIGUSR1, libc::SIGUSR2, libc::SIGCHLD, libc::SIGWINCH]);

/// Signals to register for monitor process.
pub const MONITOR_SIGNALS: &[libc::c_int] = &[
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTSTP,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGCHLD,
];

#[inline]
#[must_use]
pub fn is_forward_signal_allowed(signal: i32) -> bool {
    FORWARDABLE_SIGNALS.contains(&signal)
}

#[derive(Archive, Serialize, Deserialize, Debug)]
pub enum MonitorMessage {
    /// Signal to be forwarded to the command
    Signal(i32),
    /// Ready to start
    Edge,
}

#[derive(Archive, Serialize, Deserialize, Debug)]
pub enum ParentMessage {
    /// Command PID
    CommandPid(i32),
    /// Exit status from the command
    ExitStatus(i32),
    /// Error during execution
    Error(String),
}

pub struct Backchannel {
    stream: UnixStream,
    /// The bytes of the frame being read: on a non-blocking socket, a frame can arrive in parts.
    received: Vec<u8>,
}

impl Backchannel {
    /// # Errors
    /// Returns an error if the ``UnixStream`` pair cannot be created
    ///
    /// The backchannel sockets are created as BLOCKING. They will be registered with `poll()`,
    /// which will notify when they're ready. Then they can be read without blocking the event loop.
    pub fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = UnixStream::pair()?;
        // Keep both as blocking - poll() will notify when data is available
        Ok((Self::new(a), Self::new(b)))
    }

    const fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            received: Vec::new(),
        }
    }

    /// Write a whole frame. It is written at once, and a full non-blocking socket is waited for:
    /// a frame is never cut, whatever the peer reads in between.
    fn write_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_BACKCHANNEL_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("backchannel message too large: {} bytes", data.len()),
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        let len = (data.len() as u32).to_le_bytes();
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
        frame.extend_from_slice(&len);
        frame.extend_from_slice(data);
        trace!("backchannel: write frame len={}", data.len());
        let mut written = 0;
        while written < frame.len() {
            match self.stream.write(&frame[written..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(count) => written += count,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => self.wait_writable()?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Wait until the socket can be written again.
    fn wait_writable(&self) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            // SAFETY: `fd` is one valid pollfd that outlives the call, and the count is 1
            if unsafe { libc::poll(&raw mut fd, 1, -1) } >= 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Read one frame. On a non-blocking socket, the bytes read so far are kept and `WouldBlock`
    /// is returned until the frame is complete. Only the bytes of this frame are read: the next
    /// one stays in the socket, so that `poll()` still reports it.
    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        use std::io::Read;
        loop {
            let size = self.frame_size()?;
            let start = self.received.len();
            if start == size {
                trace!("backchannel: read frame len={}", size - FRAME_HEADER_SIZE);
                let data = self.received.split_off(FRAME_HEADER_SIZE);
                self.received.clear();
                return Ok(data);
            }
            self.received.resize(size, 0);
            match self.stream.read(&mut self.received[start..]) {
                Ok(0) => {
                    self.received.truncate(start);
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "backchannel closed",
                    ));
                }
                Ok(count) => self.received.truncate(start + count),
                Err(e) => {
                    self.received.truncate(start);
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// The size of the frame being read, header included; the size of the header alone until it
    /// is read. An invalid length means that the stream cannot be trusted anymore: the bytes read
    /// so far are dropped.
    fn frame_size(&mut self) -> io::Result<usize> {
        let Some(header) = self.received.first_chunk::<FRAME_HEADER_SIZE>() else {
            return Ok(FRAME_HEADER_SIZE);
        };
        let len = u32::from_le_bytes(*header) as usize;
        if len == 0 || len > MAX_BACKCHANNEL_MESSAGE_SIZE {
            self.received.clear();
            warn!("backchannel: invalid frame size {len}");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid backchannel message size: {len} bytes"),
            ));
        }
        Ok(FRAME_HEADER_SIZE + len)
    }

    /// # Errors
    /// Returns an error if serialization fails or if the message is too large.
    pub fn send_monitor_message(&mut self, msg: &MonitorMessage) -> io::Result<()> {
        let data = rkyv::to_bytes::<rkyv::rancor::Error>(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        trace!("backchannel: send monitor message {msg:?}");
        self.write_frame(&data)
    }

    /// # Errors
    /// Returns an error if deserialization fails, if reading from the stream fails, or if the message is too large.
    pub fn recv_monitor_message(&mut self) -> io::Result<MonitorMessage> {
        let data = self.read_frame()?;
        // SAFETY: bytes come from our own serializer over a trusted local socket.
        let msg =
            unsafe { rkyv::from_bytes_unchecked::<MonitorMessage, rkyv::rancor::Error>(&data) }
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        trace!("backchannel: recv monitor message {msg:?}");
        Ok(msg)
    }

    /// # Errors
    /// Returns an error if serialization fails or if the message is too large.
    pub fn send_parent_message(&mut self, msg: &ParentMessage) -> io::Result<()> {
        let data = rkyv::to_bytes::<rkyv::rancor::Error>(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        trace!("backchannel: send parent message {msg:?}");
        self.write_frame(&data)
    }

    /// # Errors
    /// Returns an error if deserialization fails, if reading from the stream fails
    pub fn recv_parent_message(&mut self) -> io::Result<ParentMessage> {
        let data = self.read_frame()?;
        let msg = rkyv::from_bytes::<ParentMessage, rkyv::rancor::Error>(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        trace!("backchannel: recv parent message {msg:?}");
        Ok(msg)
    }

    pub const fn get_mut(&mut self) -> &mut UnixStream {
        &mut self.stream
    }

    /// # Errors
    /// Returns an error if setting non-blocking mode fails.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> io::Result<()> {
        self.stream.set_nonblocking(nonblocking)
    }

    #[must_use]
    pub const fn get_stream(&self) -> &UnixStream {
        &self.stream
    }
}

impl std::os::fd::AsFd for Backchannel {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn backchannel_roundtrips_messages() {
        let (mut parent, mut monitor) = Backchannel::pair().expect("create backchannel pair");

        parent
            .send_monitor_message(&MonitorMessage::Signal(libc::SIGUSR1))
            .expect("send monitor message");
        match monitor
            .recv_monitor_message()
            .expect("receive monitor message")
        {
            MonitorMessage::Signal(signal) => assert_eq!(signal, libc::SIGUSR1),
            MonitorMessage::Edge => panic!("unexpected monitor message"),
        }

        monitor
            .send_parent_message(&ParentMessage::CommandPid(4242))
            .expect("send parent message");
        match parent
            .recv_parent_message()
            .expect("receive parent message")
        {
            ParentMessage::CommandPid(pid) => assert_eq!(pid, 4242),
            ParentMessage::ExitStatus(_) | ParentMessage::Error(_) => {
                panic!("unexpected parent message")
            }
        }

        parent
            .set_nonblocking(true)
            .expect("keep nonblocking mode configurable");
    }

    #[test]
    fn backchannel_rejects_oversized_frames() {
        let (mut parent, _) = Backchannel::pair().expect("create backchannel pair");
        let payload = vec![0u8; MAX_BACKCHANNEL_MESSAGE_SIZE + 1];

        let error = parent
            .write_frame(&payload)
            .expect_err("oversized frame must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn backchannel_rejects_invalid_frame_size() {
        let (mut sender, mut receiver) = Backchannel::pair().expect("create backchannel pair");

        sender
            .get_mut()
            .write_all(&0u32.to_le_bytes())
            .expect("write invalid frame header");

        let error = receiver
            .read_frame()
            .expect_err("zero-sized frame must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn backchannel_rejects_truncated_parent_message() {
        let (mut sender, mut receiver) = Backchannel::pair().expect("create backchannel pair");

        // Serialize a valid message first to get real serialized bytes
        let msg = ParentMessage::CommandPid(4242);
        let full_data =
            rkyv::to_bytes::<rkyv::rancor::Error>(&msg).expect("serialize parent message");

        // Write the full length of the serialized data, but only send part of it
        #[allow(clippy::cast_possible_truncation)]
        let truncated_len = (full_data.len() / 2) as u32;
        sender
            .get_mut()
            .write_all(&truncated_len.to_le_bytes())
            .expect("write truncated frame header");
        sender
            .get_mut()
            .write_all(&full_data[..truncated_len as usize])
            .expect("write partial frame payload");

        let error = receiver
            .recv_parent_message()
            .expect_err("truncated frame must fail gracefully");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// The bytes of one frame, as the sender writes them.
    fn frame_bytes(msg: &ParentMessage) -> Vec<u8> {
        use std::io::Read;
        let (mut sender, mut receiver) = Backchannel::pair().expect("create backchannel pair");
        sender
            .send_parent_message(msg)
            .expect("send parent message");
        drop(sender);
        let mut frame = Vec::new();
        receiver
            .get_mut()
            .read_to_end(&mut frame)
            .expect("read the frame");
        frame
    }

    // The monitor can be preempted between the length and the payload of a frame: the runner
    // reads a non-blocking socket and must keep what it already read until the frame is complete.
    #[test]
    fn backchannel_keeps_a_frame_split_across_reads() {
        let frame = frame_bytes(&ParentMessage::ExitStatus(0));
        let (mut monitor, mut runner) = Backchannel::pair().expect("create backchannel pair");
        runner.set_nonblocking(true).expect("set nonblocking");

        for split in 1..frame.len() {
            monitor
                .get_mut()
                .write_all(&frame[..split])
                .expect("write the first part");
            let error = runner
                .recv_parent_message()
                .expect_err("a part of a frame is not a message");
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "split at {split}");

            monitor
                .get_mut()
                .write_all(&frame[split..])
                .expect("write the rest");
            match runner.recv_parent_message() {
                Ok(ParentMessage::ExitStatus(status)) => assert_eq!(status, 0),
                other => panic!("split at {split}: unexpected result {other:?}"),
            }
        }
    }

    #[test]
    fn backchannel_reads_a_frame_written_byte_by_byte() {
        let frame = frame_bytes(&ParentMessage::CommandPid(4242));
        let (mut monitor, mut runner) = Backchannel::pair().expect("create backchannel pair");
        runner.set_nonblocking(true).expect("set nonblocking");

        let (last, first) = frame.split_last().expect("a frame is not empty");
        for byte in first {
            monitor
                .get_mut()
                .write_all(std::slice::from_ref(byte))
                .expect("write one byte");
            let error = runner
                .recv_parent_message()
                .expect_err("a part of a frame is not a message");
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        }
        monitor
            .get_mut()
            .write_all(std::slice::from_ref(last))
            .expect("write the last byte");
        match runner.recv_parent_message() {
            Ok(ParentMessage::CommandPid(pid)) => assert_eq!(pid, 4242),
            other => panic!("unexpected result {other:?}"),
        }
    }

    // The monitor handles one message per readable event: reading a frame must not take the
    // bytes of the next one, or poll would not report them anymore.
    #[test]
    fn backchannel_leaves_the_next_frame_in_the_socket() {
        use std::os::fd::AsRawFd;
        let (mut runner, mut monitor) = Backchannel::pair().expect("create backchannel pair");
        monitor.set_nonblocking(true).expect("set nonblocking");
        runner
            .send_monitor_message(&MonitorMessage::Signal(libc::SIGUSR1))
            .expect("send a signal");
        runner
            .send_monitor_message(&MonitorMessage::Edge)
            .expect("send the edge");

        match monitor.recv_monitor_message() {
            Ok(MonitorMessage::Signal(signal)) => assert_eq!(signal, libc::SIGUSR1),
            other => panic!("unexpected result {other:?}"),
        }
        let mut fd = libc::pollfd {
            fd: monitor.get_stream().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `fd` is one valid pollfd that outlives the call, and the timeout is zero
        let ready = unsafe { libc::poll(&raw mut fd, 1, 0) };
        assert_eq!(ready, 1, "the second frame must still be readable");
        assert!(matches!(
            monitor.recv_monitor_message(),
            Ok(MonitorMessage::Edge)
        ));
    }

    // A frame sent on a full non-blocking socket waits for room instead of being cut.
    #[test]
    fn backchannel_waits_for_room_when_the_socket_is_full() {
        use std::io::Read;
        let (mut monitor, mut runner) = Backchannel::pair().expect("create backchannel pair");
        monitor.set_nonblocking(true).expect("set nonblocking");
        runner
            .get_mut()
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("set a read timeout");

        let chunk = [0xffu8; 4096];
        let mut filled = 0;
        loop {
            match monitor.get_mut().write(&chunk) {
                Ok(written) => filled += written,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill the socket: {e}"),
            }
        }
        // the reader drains the socket only once the frame is being sent on a full socket
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let mut filler = vec![0u8; filled];
            runner
                .get_mut()
                .read_exact(&mut filler)
                .expect("drain the filler");
            runner.recv_parent_message()
        });

        monitor
            .send_parent_message(&ParentMessage::ExitStatus(7))
            .expect("the frame is sent whole");
        match reader.join().expect("the reader thread ends") {
            Ok(ParentMessage::ExitStatus(status)) => assert_eq!(status, 7),
            other => panic!("unexpected result {other:?}"),
        }
    }
}
