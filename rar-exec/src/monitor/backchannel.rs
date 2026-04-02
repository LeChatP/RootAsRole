/// This backchannel uses rkyv instead of sudo-rs implementation because I don't want to maintain a custom serialization format
/// and rkyv is clearly suitable and performant. I think serde would be too long to setup for this use case.
use rkyv::{Archive, Deserialize, Serialize};
use std::io::{self, Write};
use std::os::unix::net::UnixStream;

pub const MAX_BACKCHANNEL_MESSAGE_SIZE: usize = 64 * 1024;

macro_rules! signals {
    (core + [$($extra:expr),* $(,)?]) => {
        &[
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGQUIT,
            libc::SIGHUP,
            libc::SIGCONT,
            libc::SIGTSTP,
            $($extra),*
        ]
    };
}

/// Signals that can be forwarded from runner to command.
pub const FORWARDABLE_SIGNALS: &[libc::c_int] = signals!(core + [libc::SIGUSR1, libc::SIGUSR2]);

/// Signals to register for no-pty execution (runner).
pub const RUNNER_SIGNALS_NO_PTY: &[libc::c_int] = signals!(core + [libc::SIGCHLD]);

/// Signals to register for pty execution (runner).
pub const RUNNER_SIGNALS_WITH_PTY: &[libc::c_int] =
    signals!(core + [libc::SIGWINCH, libc::SIGCHLD]);

/// Signals to register for monitor process.
pub const MONITOR_SIGNALS: &[libc::c_int] =
    signals!(core + [libc::SIGUSR1, libc::SIGUSR2, libc::SIGCHLD]);

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
}

impl Backchannel {
    /// # Errors
    /// Returns an error if the ``UnixStream`` pair cannot be created or if setting non-blocking
    pub fn pair() -> io::Result<(Self, Self)> {
        let (a, b) = UnixStream::pair()?;
        a.set_nonblocking(true)?;
        b.set_nonblocking(true)?;
        Ok((Self { stream: a }, Self { stream: b }))
    }

    fn write_frame(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > MAX_BACKCHANNEL_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("backchannel message too large: {} bytes", data.len()),
            ));
        }
        #[allow(clippy::cast_possible_truncation)]
        let len = (data.len() as u32).to_le_bytes();
        self.stream.write_all(&len)?;
        self.stream.write_all(data)?;
        Ok(())
    }

    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        use std::io::Read;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_BACKCHANNEL_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid backchannel message size: {len} bytes"),
            ));
        }

        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data)?;
        Ok(data)
    }

    /// # Errors
    /// Returns an error if serialization fails or if the message is too large.
    pub fn send_monitor_message(&mut self, msg: &MonitorMessage) -> io::Result<()> {
        let data = rkyv::to_bytes::<rkyv::rancor::Error>(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.write_frame(&data)
    }

    /// # Errors
    /// Returns an error if deserialization fails, if reading from the stream fails, or if the message is too large.
    pub fn recv_monitor_message(&mut self) -> io::Result<MonitorMessage> {
        let data = self.read_frame()?;
        // SAFETY: bytes come from our own serializer over a trusted local socket.
        unsafe { rkyv::from_bytes_unchecked::<MonitorMessage, rkyv::rancor::Error>(&data) }
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// # Errors
    /// Returns an error if serialization fails or if the message is too large.
    pub fn send_parent_message(&mut self, msg: &ParentMessage) -> io::Result<()> {
        let data = rkyv::to_bytes::<rkyv::rancor::Error>(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.write_frame(&data)
    }

    /// # Errors
    /// Returns an error if deserialization fails, if reading from the stream fails
    pub fn recv_parent_message(&mut self) -> io::Result<ParentMessage> {
        let data = self.read_frame()?;
        unsafe { rkyv::from_bytes_unchecked::<ParentMessage, rkyv::rancor::Error>(&data) }
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
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
