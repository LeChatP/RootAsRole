use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

use crate::monitor::backchannel::{
    Backchannel, MonitorMessage, ParentMessage, RUNNER_SIGNALS_NO_PTY, RUNNER_SIGNALS_WITH_PTY,
    is_forward_signal_allowed,
};
use crate::orchestrator::{Orchestrator, PreExecContext};

use super::event::{EventRegistry, PollEvent, Process, StopReason};
use super::pipe::{IoLogger, Pipe};
use super::pty::{Pty, PtyLeader};
use super::signal::{SignalStream, register_signal_handler};
use super::terminal::UserTerm;

pub struct SimpleFileLogger {
    file: std::fs::File,
}

impl SimpleFileLogger {
    /// # Errors
    /// Returns an error if the log file cannot be created or opened.
    /// This can happen due to reasons such as insufficient permissions, invalid file path, or disk issues.
    pub fn new(path: &str) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }
}

impl IoLogger for SimpleFileLogger {
    fn log_input(&mut self, data: &[u8]) {
        use std::io::Write;
        let _ = write!(self.file, "IN {}: ", data.len());
        let _ = self.file.write_all(data);
        let _ = self.file.write_all(b"\n");
    }

    fn log_output(&mut self, data: &[u8]) {
        use std::io::Write;
        let _ = write!(self.file, "OUT {}: ", data.len());
        let _ = self.file.write_all(data);
        let _ = self.file.write_all(b"\n");
    }
}

pub struct ExecRunner {
    pipe: Pipe<UserTerm, PtyLeader>,
    signal_stream: &'static SignalStream,
    // monitor_pid is used instead of child process handle
    monitor_pid: i32,
    backchannel: Backchannel,
    command_pid: i32,
}

#[derive(Clone, Copy, Debug)]
pub enum RunnerEvent {
    PipeLeft(PollEvent),
    PipeRight(PollEvent),
    Signal,
    Backchannel,
}

impl Process for ExecRunner {
    type Event = RunnerEvent;
    type Break = io::Error;
    type Exit = std::process::ExitStatus;

    fn on_event(&mut self, event: Self::Event, registry: &mut EventRegistry<Self>) {
        match event {
            RunnerEvent::PipeLeft(e) => {
                if let Err(err) = self.pipe.on_left_event(e, registry) {
                    registry.set_break(err);
                }
            }
            RunnerEvent::PipeRight(e) => {
                if let Err(err) = self.pipe.on_right_event(e, registry) {
                    if err.kind() == io::ErrorKind::UnexpectedEof
                        || err.kind() == io::ErrorKind::BrokenPipe
                    {
                        self.check_monitor_exit(registry);
                    } else {
                        registry.set_break(err);
                    }
                }
            }
            RunnerEvent::Signal => {
                // Consume all pending signals
                loop {
                    match self.signal_stream.recv() {
                        Ok(info) => self.handle_signal(info.signal, registry),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            registry.set_break(e);
                            break;
                        }
                    }
                }
            }
            RunnerEvent::Backchannel => {
                loop {
                    match self.backchannel.recv_parent_message() {
                        Ok(msg) => self.handle_monitor_message(msg, registry),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            // If monitor closes connection, it usually means it exited.
                            if e.kind() == io::ErrorKind::UnexpectedEof
                                || e.kind() == std::io::ErrorKind::ConnectionReset
                            {
                                self.check_monitor_exit(registry);
                                break;
                            }
                            registry.set_break(e);
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl ExecRunner {
    fn handle_signal(&mut self, signal: libc::c_int, registry: &mut EventRegistry<Self>) {
        match signal {
            libc::SIGCHLD => {
                // Potentially monitor exited
                self.check_monitor_exit(registry);
            }
            libc::SIGWINCH => {
                // Propagate resize
                if let Ok(size) = self.pipe.left().get_size() {
                    let _ = self.pipe.right().set_size(&size);
                }
            }
            _ => {
                // Forward signal to monitor process via backchannel
                if is_forward_signal_allowed(signal)
                    && self
                        .backchannel
                        .send_monitor_message(&MonitorMessage::Signal(signal))
                        .is_err()
                {
                    // If send fails, monitor is likely gone
                    self.check_monitor_exit(registry);
                }
            }
        }
    }

    fn handle_monitor_message(&mut self, msg: ParentMessage, registry: &mut EventRegistry<Self>) {
        match msg {
            ParentMessage::CommandPid(pid) => {
                self.command_pid = pid;
            }
            ParentMessage::ExitStatus(status) => {
                registry.set_exit(std::process::ExitStatus::from_raw(status));
            }
            ParentMessage::Error(err) => {
                registry.set_break(io::Error::other(err));
            }
        }
    }

    fn check_monitor_exit(&mut self, registry: &mut EventRegistry<Self>) {
        let mut status = 0;
        let res = unsafe { libc::waitpid(self.monitor_pid, &raw mut status, libc::WNOHANG) };
        if res > 0 {
            registry.set_exit(std::process::ExitStatus::from_raw(status));
            let _ = self.pipe.flush_left();
        }
    }
}

/// # Errors
/// Returns an error if the execution fails due to :
/// - Failure to fork process
/// - Failure in setting up the PTY
/// - Failure in setting up signal handlers
/// - Failure in the backchannel communication
/// - Failure in the orchestrator's pre-exec function
/// - Failure in spawning the command execution
pub fn run_no_pty(
    mut command: Command,
    orchestrator: Orchestrator,
) -> io::Result<std::process::ExitStatus> {
    // initialize signals
    let signal_stream = SignalStream::init()?;
    for &sig in RUNNER_SIGNALS_NO_PTY {
        register_signal_handler(sig)?;
    }

    // orchestration
    unsafe {
        let ctx = PreExecContext::empty();
        command.pre_exec(move || orchestrator.run(&ctx));
    }

    let mut child = command.spawn()?;

    // event loop for signals
    loop {
        match signal_stream.recv() {
            Ok(info) => {
                match info.signal {
                    libc::SIGCHLD => {
                        if let Some(status) = child.try_wait()? {
                            return Ok(status);
                        }
                    }
                    _ => {
                        // Forward signal
                        if is_forward_signal_allowed(info.signal) {
                            unsafe { libc::kill(child.id().cast_signed(), info.signal) };
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e),
        }
    }
}

/// # Errors
/// Returns an error if the execution fails due to :
/// - Failure to fork process
/// - Failure in setting up the PTY
/// - Failure in setting up signal handlers
/// - Failure in the backchannel communication
/// - Failure in the orchestrator's pre-exec function
/// - Failure in spawning the command execution
pub fn run(
    command: Command,
    orchestrator: Orchestrator,
    logger: Option<Box<dyn IoLogger>>,
) -> io::Result<std::process::ExitStatus> {
    match UserTerm::open() {
        Ok(term) => run_with_pty(command, orchestrator, logger, term),
        Err(_) => run_no_pty(command, orchestrator),
    }
}

/// # Errors
/// Returns an error if the execution fails due to :
/// - Failure to fork process
/// - Failure in setting up the PTY
/// - Failure in setting up signal handlers
/// - Failure in the backchannel communication
/// - Failure in the orchestrator's pre-exec function
/// - Failure in spawning the command execution
pub fn run_with_pty(
    command: Command,
    orchestrator: Orchestrator,
    logger: Option<Box<dyn IoLogger>>,
    mut user_term: UserTerm,
) -> io::Result<std::process::ExitStatus> {
    // initialize signals
    // SIGTTIN and SIGTTOU are ignored to prevent the runner from being suspended
    // when interacting with the terminal in background
    let signal_stream = SignalStream::init()?;
    for &sig in RUNNER_SIGNALS_WITH_PTY {
        register_signal_handler(sig)?;
    }
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    user_term.set_raw_mode(true, true)?;

    let pty = Pty::open()?;
    if let Ok(sz) = user_term.get_size() {
        pty.leader.set_size(&sz)?;
    }

    // Create backchannel
    let (mut parent_channel, monitor_channel) = Backchannel::pair()?;

    // FORK: Separate Parent and Monitor
    // SAFETY: Single threaded at this point
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // --- MONITOR PROCESS ---
        // Close parent execution resources
        drop(pty.leader);
        // signal_stream is static reference, no drop needed

        // Execute Monitor Logic
        let res = crate::monitor::exec_monitor_process(
            pty.follower,
            command,
            orchestrator,
            monitor_channel,
            None,
        );

        if let Err(e) = res {
            eprintln!("Monitor failed: {e}");
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::_exit(0) }; // Should not be reached if exec works? No, exec is inside exec_monitor
    }

    // --- PARENT PROCESS ---
    drop(pty.follower); // Parent doesn't need follower
    drop(monitor_channel); // Parent doesn't need monitor channel

    pty.leader.set_nonblocking()?;

    let mut registry = EventRegistry::new();

    let pipe = Pipe::new(
        user_term,
        pty.leader,
        &mut registry,
        RunnerEvent::PipeLeft,
        RunnerEvent::PipeRight,
        logger,
    );

    // signals
    registry.register_event(signal_stream, PollEvent::Readable, |_| RunnerEvent::Signal);
    registry.register_event(parent_channel.get_mut(), PollEvent::Readable, |_| {
        RunnerEvent::Backchannel
    });

    let mut runner = ExecRunner {
        pipe,
        signal_stream,
        monitor_pid: pid, // Parent tracks monitor
        backchannel: parent_channel,
        command_pid: 0,
    };

    // HANDSHAKE 1: Send "Start" (Edge) to monitor to let it spawn the command
    // We are ready to handle events.
    if let Err(e) = runner
        .backchannel
        .send_monitor_message(&MonitorMessage::Edge)
    {
        return Err(io::Error::other(format!("Failed to start monitor: {e}")));
    }

    let res = registry.event_loop(&mut runner);

    // HANDSHAKE 2: Send "Stop" (Edge) to tell monitor to exit
    // If we're here, we are done with outputs.
    // Monitor might already be waiting.
    // We ignore error here as monitor might have died already.
    let _ = runner
        .backchannel
        .send_monitor_message(&MonitorMessage::Edge);

    // restore
    runner.pipe.left_mut().restore(true)?;

    match res {
        StopReason::Exit(status) => {
            let _ = runner.pipe.flush_left();
            Ok(status)
        }
        StopReason::Break(e) => Err(e),
    }
}
