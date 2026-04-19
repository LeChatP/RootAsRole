use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

use log::error;

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
        if let Err(e) = write!(self.file, "IN {}: ", data.len()) {
            error!("Logger: failed to write input prefix: {e}");
            return;
        }
        if let Err(e) = self.file.write_all(data) {
            error!("Logger: failed to write input data: {e}");
            return;
        }
        if let Err(e) = self.file.write_all(b"\n") {
            error!("Logger: failed to write input newline: {e}");
        }
    }

    fn log_output(&mut self, data: &[u8]) {
        use std::io::Write;
        if let Err(e) = write!(self.file, "OUT {}: ", data.len()) {
            error!("Logger: failed to write output prefix: {e}");
            return;
        }
        if let Err(e) = self.file.write_all(data) {
            error!("Logger: failed to write output data: {e}");
            return;
        }
        if let Err(e) = self.file.write_all(b"\n") {
            error!("Logger: failed to write output newline: {e}");
        }
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
    // initialize signals BEFORE spawning child to minimize race window
    let signal_stream = SignalStream::init()?;
    for &sig in RUNNER_SIGNALS_NO_PTY {
        register_signal_handler(sig)?;
    }

    // orchestration: set up pre_exec hooks before spawning
    unsafe {
        let ctx = PreExecContext::empty();
        command.pre_exec(move || orchestrator.run(&ctx));
    }

    let mut child = command.spawn()?;

    // event loop for signals
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }

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
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
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
        drop(parent_channel); // Explicitly drop parent's communication channel
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
            error!("Monitor failed: {e}");
            unsafe { libc::_exit(1) };
        }
        // SAFETY: exec_monitor_process should have replaced the process image via exec().
        // If we reach this point, exec() failed and we already exited above with code 1.
        // This line is unreachable in normal execution.
        unreachable!("exec_monitor_process must either exec or exit");
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

#[cfg(test)]
mod tests {
    use super::{IoLogger, SimpleFileLogger, run_no_pty};
    use crate::orchestrator::{Orchestrator, PreExecContext, PreExecStep, Stage};
    use serial_test::serial;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::unnecessary_wraps)]
    unsafe fn pre_exec_noop(_: PreExecContext) -> io::Result<()> {
        Ok(())
    }

    unsafe fn pre_exec_set_test_env(_: PreExecContext) -> io::Result<()> {
        let key = b"RAR_EXEC_TEST_FLAG\0";
        let value = b"1\0";
        let rc = unsafe { libc::setenv(key.as_ptr().cast(), value.as_ptr().cast(), 1) };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    unsafe fn pre_exec_fail(_: PreExecContext) -> io::Result<()> {
        Err(io::Error::other("pre-exec failure"))
    }

    static NOOP_STEPS: &[PreExecStep] = &[PreExecStep {
        stage: Stage::SESSION,
        run: pre_exec_noop,
    }];

    static SET_ENV_STEPS: &[PreExecStep] = &[PreExecStep {
        stage: Stage::SESSION,
        run: pre_exec_set_test_env,
    }];

    static FAIL_STEPS: &[PreExecStep] = &[PreExecStep {
        stage: Stage::SESSION,
        run: pre_exec_fail,
    }];

    fn unique_log_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rar_exec_runner_{name}_{}_{}.log",
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn simple_file_logger_writes_expected_prefixes() {
        let path = unique_log_path("prefixes");
        let mut logger =
            SimpleFileLogger::new(path.to_str().expect("valid temporary file path as UTF-8"))
                .expect("create logger");

        logger.log_input(b"hello");
        logger.log_output(b"world");

        let content = fs::read_to_string(&path).expect("read log file");
        assert!(content.contains("IN 5: hello\n"));
        assert!(content.contains("OUT 5: world\n"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn simple_file_logger_appends_across_instances() {
        let path = unique_log_path("append");

        {
            let mut first =
                SimpleFileLogger::new(path.to_str().expect("valid temporary file path as UTF-8"))
                    .expect("create first logger");
            first.log_input(b"one");
        }

        {
            let mut second =
                SimpleFileLogger::new(path.to_str().expect("valid temporary file path as UTF-8"))
                    .expect("create second logger");
            second.log_output(b"two");
        }

        let content = fs::read_to_string(&path).expect("read log file");
        assert!(content.contains("IN 3: one\n"));
        assert!(content.contains("OUT 3: two\n"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn simple_file_logger_supports_empty_payloads() {
        let path = unique_log_path("empty");
        let mut logger =
            SimpleFileLogger::new(path.to_str().expect("valid temporary file path as UTF-8"))
                .expect("create logger");

        logger.log_input(&[]);
        logger.log_output(&[]);

        let content = fs::read_to_string(&path).expect("read log file");
        assert!(content.contains("IN 0: \n"));
        assert!(content.contains("OUT 0: \n"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn run_no_pty_returns_command_exit_code() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("exit 7");

        let status = run_no_pty(command, Orchestrator::new(NOOP_STEPS)).expect("run command");
        assert_eq!(status.code(), Some(7));
    }

    #[serial]
    #[test]
    fn run_no_pty_applies_pre_exec_orchestrator() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test \"$RAR_EXEC_TEST_FLAG\" = \"1\"");

        let status = run_no_pty(command, Orchestrator::new(SET_ENV_STEPS)).expect("run command");
        assert!(status.success());
    }

    #[serial]
    #[test]
    fn run_no_pty_propagates_pre_exec_failure() {
        let command = Command::new("/usr/bin/true");
        let error = run_no_pty(command, Orchestrator::new(FAIL_STEPS));
        assert!(error.is_err());
    }

    #[serial]
    #[test]
    fn run_no_pty_forwards_signals_to_child() {
        let sender = thread::spawn(|| {
            thread::sleep(std::time::Duration::from_millis(250));
            unsafe {
                libc::kill(libc::getpid(), libc::SIGHUP);
            }
        });

        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("trap 'exit 42' HUP; while :; do sleep 1; done");

        let status = run_no_pty(command, Orchestrator::new(NOOP_STEPS)).expect("run command");
        sender.join().expect("signal sender thread joined");

        assert_eq!(status.code(), Some(42));
    }
}
