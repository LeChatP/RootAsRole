use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};

use log::{debug, error, trace, warn};

use crate::monitor::backchannel::{
    Backchannel, MonitorMessage, ParentMessage, RUNNER_SIGNALS_NO_PTY, RUNNER_SIGNALS_WITH_PTY,
    is_forward_signal_allowed,
};
use crate::orchestrator::{Orchestrator, PreExecContext};

use super::event::{EventRegistry, PollEvent, Process, StopReason};
use super::pipe::{IoLogger, Pipe, io_logger_sealed};
use super::pty::{Pty, PtyLeader};
use super::signal::{SignalStream, register_signal_handler};
use super::terminal::{ProcessId, TermSize, TerminalExt, UserTerm};

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

impl io_logger_sealed::Sealed for SimpleFileLogger {
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
    parent_pgrp: ProcessId,
    tty_size: TermSize,
    foreground: bool,
    term_raw: bool,
    preserve_oflag: bool,
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
                trace!("runner: pipe left event {e:?}");
                if let Err(err) = self.pipe.on_left_event(e, registry) {
                    registry.set_break(err);
                }
            }
            RunnerEvent::PipeRight(e) => {
                trace!("runner: pipe right event {e:?}");
                if let Err(err) = self.pipe.on_right_event(e, registry) {
                    if err.kind() == io::ErrorKind::UnexpectedEof
                        || err.kind() == io::ErrorKind::BrokenPipe
                    {
                        debug!("runner: pipe right closed, checking monitor exit");
                        self.check_monitor_exit(registry);
                    } else {
                        registry.set_break(err);
                    }
                }
            }
            RunnerEvent::Signal => {
                trace!("runner: signal event");
                // Consume all pending signals
                loop {
                    match self.signal_stream.recv() {
                        Ok(info) => self.handle_signal(info, registry),
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            warn!("runner: signal recv error: {e}");
                            registry.set_break(e);
                            break;
                        }
                    }
                }
            }
            RunnerEvent::Backchannel => self.on_backchannel_readable(registry),
        }
    }
}

impl ExecRunner {
    fn handle_signal(&mut self, info: crate::signal::SignalInfo, registry: &mut EventRegistry<Self>) {
        debug!("runner: got signal {} from pid {}", info.signal, info.pid);
        match info.signal {
            libc::SIGCHLD => {
                // Potentially monitor exited
                self.check_monitor_exit(registry);
            }
            libc::SIGCONT => {
                debug!("runner: SIGCONT -> resume terminal");
                let _ = self.resume_terminal();
            }
            libc::SIGWINCH => {
                // Propagate resize
                debug!("runner: SIGWINCH -> handle resize");
                let _ = self.handle_sigwinch();
            }
            _ => {
                // Forward signal to monitor process via backchannel
                if is_forward_signal_allowed(info.signal)
                    && !self.is_self_terminating(info.pid)
                    && self
                        .backchannel
                        .send_monitor_message(&MonitorMessage::Signal(info.signal))
                        .is_err()
                {
                    // If send fails, monitor is likely gone
                    warn!("runner: failed to forward signal {}, checking monitor exit", info.signal);
                    self.check_monitor_exit(registry);
                }
            }
        }
    }

    fn on_backchannel_readable(&mut self, registry: &mut EventRegistry<Self>) {
        trace!("runner: backchannel readable");
        loop {
            match self.backchannel.recv_parent_message() {
                Ok(ParentMessage::CommandPid(pid)) => {
                    debug!("runner: command pid set to {pid}");
                    self.command_pid = pid;
                }
                Ok(ParentMessage::ExitStatus(status)) => {
                    debug!("runner: exit status received: {status}");
                    registry.set_exit(std::process::ExitStatus::from_raw(status));
                    break;
                }
                Ok(ParentMessage::Error(err)) => {
                    warn!("runner: error from monitor: {err}");
                    registry.set_break(io::Error::other(err));
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // If monitor closes connection, it usually means it exited.
                    if e.kind() == io::ErrorKind::UnexpectedEof
                        || e.kind() == std::io::ErrorKind::ConnectionReset
                    {
                        warn!("runner: backchannel closed, checking monitor exit");
                        self.check_monitor_exit(registry);
                        break;
                    }
                    warn!("runner: backchannel recv error: {e}");
                    registry.set_break(e);
                    break;
                }
            }
        }
    }

    fn handle_sigwinch(&mut self) -> io::Result<()> {
        let new_size = self.pipe.left().get_size()?;
        if new_size != self.tty_size {
            debug!("runner: resize {} -> {}", self.tty_size, new_size);
            self.pipe.right().set_size(&new_size)?;
            self.tty_size = new_size;

            if self.command_pid > 0 {
                debug!("runner: send SIGWINCH to pgid {}", self.command_pid);
                unsafe { libc::killpg(self.command_pid, libc::SIGWINCH) };
            }
        }
        Ok(())
    }

    fn resume_terminal(&mut self) -> io::Result<()> {
        if self.term_raw && self.foreground {
            debug!("runner: restoring raw mode (preserve_oflag={})", self.preserve_oflag);
            self.pipe
                .left_mut()
                .set_raw_mode(true, self.preserve_oflag)?;
        }
        Ok(())
    }

    fn is_self_terminating(&self, signaler_pid: libc::pid_t) -> bool {
        if signaler_pid <= 0 || self.command_pid <= 0 {
            return false;
        }

        if signaler_pid == self.command_pid {
            return true;
        }

        let signaler_pgrp = unsafe { libc::getpgid(signaler_pid) };
        signaler_pgrp == self.command_pid
    }

    fn check_monitor_exit(&mut self, registry: &mut EventRegistry<Self>) {
        let mut status = 0;
        let res = unsafe { libc::waitpid(self.monitor_pid, &raw mut status, libc::WNOHANG) };
        if res > 0 {
            debug!("runner: monitor exited with status {status}");
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
    let original_set = block_all_signals();

    // initialize signals BEFORE spawning child to minimize race window
    let signal_stream = SignalStream::init()?;
    for &sig in RUNNER_SIGNALS_NO_PTY {
        register_signal_handler(sig)?;
    }
    debug!("runner(no_pty): signal handlers installed");

    // orchestration: set up pre_exec hooks before spawning
    unsafe {
        let ctx = PreExecContext::empty();
        command.pre_exec(move || orchestrator.run(&ctx));
    }

    let mut child = command.spawn()?;
    let child_pid = i32::try_from(child.id())
        .map_err(|_| io::Error::other("child pid out of range"))?;
    debug!("runner(no_pty): child pid {child_pid}");

    restore_signals(original_set);

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
                    libc::SIGALRM => {
                        unsafe { libc::kill(child_pid, libc::SIGKILL) };
                    }
                    libc::SIGWINCH => {
                        unsafe { libc::kill(child_pid, libc::SIGWINCH) };
                    }
                    _ => {
                        if info.pid > 0 && info.pid == child_pid {
                            continue;
                        }
                        // Forward signal
                        if is_forward_signal_allowed(info.signal) {
                            unsafe { libc::kill(child_pid, info.signal) };
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

/// This function manages command execution with a Pty, and TWO forks (so 3 processes):
///
/// 1. Parent - monitor signals and I/O
/// 2. Monitor - forward signals, detect issues (command exits)
/// 3. Command - the executed command
///
/// (Parent --> monitor --> Command)
///
/// This allows to :
/// - Better signal management
/// - Better error management
/// - Better termination process
/// - Better TTY management.
///
/// # Errors
/// Returns an error if the execution fails due to :
/// - Failure to fork process
/// - Failure in setting up the PTY
/// - Failure in setting up signal handlers
/// - Failure in the backchannel communication
/// - Failure in the orchestrator's pre-exec function
/// - Failure in spawning the command execution
#[allow(clippy::too_many_lines)]
pub fn run_with_pty(
    command: Command,
    orchestrator: Orchestrator,
    logger: Option<Box<dyn IoLogger>>,
    mut user_term: UserTerm,
) -> io::Result<std::process::ExitStatus> {
    let original_set = block_all_signals();

    let parent_pgrp = ProcessId::new(unsafe { libc::getpgrp() });
    let mut foreground = user_term
        .as_tty()
        .ok()
        .and_then(|tty| tty.tcgetpgrp().ok())
        .is_some_and(|tty_pgrp| tty_pgrp == parent_pgrp);

    let mut exec_bg = false;
    let mut preserve_oflag = false;
    let mut term_raw = false;

    // initialize signals
    // SIGTTIN and SIGTTOU are ignored to prevent the runner from being suspended
    // when interacting with the terminal in background
    let signal_stream = SignalStream::init()?;
    for &sig in RUNNER_SIGNALS_WITH_PTY {
        register_signal_handler(sig)?;
    }
    debug!("runner(pty): signal handlers installed");
    // we ignore SIGTTIN and SIGTOU, no suspend here.
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    // Create Pty
    let pty = Pty::open()?;
    let tty_size = user_term.get_size().unwrap_or_else(|_| TermSize::new(0, 0));
    pty.leader.set_size(&tty_size)?; // set window size by default, resizing comes with features
    debug!("runner(pty): initial tty size {tty_size}");

    let mut command = command;
    let mut stdin_set = false;
    let mut stdout_set = false;
    let mut stderr_set = false;

    if !std::io::stdin().is_terminal_for_pgrp(parent_pgrp) {
        debug!("runner(pty): stdin not a terminal for parent pgrp");
        if std::io::stdin().is_pipe_or_socket() {
            exec_bg = true;
        }
        command.stdin(Stdio::inherit());
        stdin_set = true;
    }

    if !std::io::stdout().is_terminal_for_pgrp(parent_pgrp) {
        debug!("runner(pty): stdout not a terminal for parent pgrp");
        if std::io::stdout().is_pipe_or_socket() {
            exec_bg = true;
            preserve_oflag = true;
        }
        command.stdout(Stdio::inherit());
        stdout_set = true;
    }

    if !std::io::stderr().is_terminal_for_pgrp(parent_pgrp) {
        debug!("runner(pty): stderr not a terminal for parent pgrp");
        command.stderr(Stdio::inherit());
        stderr_set = true;
    }

    if std::io::stdout().is_pipe_or_socket() {
        debug!("runner(pty): stdout is pipe/socket -> background");
        foreground = false;
    }

    if !stdin_set {
        command.stdin(Stdio::from(pty.follower.try_clone()?));
    }
    if !stdout_set {
        command.stdout(Stdio::from(pty.follower.try_clone()?));
    }
    if !stderr_set {
        command.stderr(Stdio::from(pty.follower.try_clone()?));
    }

    if foreground {
        debug!("runner(pty): enabling raw mode preserve_oflag={preserve_oflag}");
        user_term.set_raw_mode(true, preserve_oflag)?;
        term_raw = true;
    }

    // Copy terminal settings from user terminal to PTY follower to ensure interactive I/O works
    user_term.copy_to(&pty.follower)?;

    // Create backchannel
    let (mut parent_channel, monitor_channel) = Backchannel::pair()?;
    debug!("runner(pty): backchannel created");

    // TODO: Verify if there isn't a better API for forking
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
            original_set.as_ref(),
            foreground && !exec_bg,
        );

        if let Err(e) = res {
            error!("Monitor failed: {e}");
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::exit(0) };
    }

    // --- PARENT PROCESS ---
    drop(command);
    drop(pty.follower); // Parent doesn't need follower
    drop(monitor_channel); // Parent doesn't need monitor channel

    pty.leader.set_nonblocking()?;
    debug!("runner(pty): pty leader set nonblocking");

    let mut registry = EventRegistry::new();

    let mut pipe = Pipe::new(
        user_term,
        pty.leader,
        &mut registry,
        RunnerEvent::PipeLeft,
        RunnerEvent::PipeRight,
        logger,
    );

    if !foreground || exec_bg {
        debug!("runner(pty): disabling input (foreground={foreground}, exec_bg={exec_bg})");
        pipe.disable_input(&mut registry);
    }

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
        parent_pgrp,
        tty_size,
        foreground,
        term_raw,
        preserve_oflag,
    };

    // HANDSHAKE 1: Send "Start" (Edge) to monitor to let it spawn the command
    // We are ready to handle events.
    if let Err(e) = runner
        .backchannel
        .send_monitor_message(&MonitorMessage::Edge)
    {
        return Err(io::Error::other(format!("Failed to start monitor: {e}")));
    }
    debug!("runner(pty): sent start edge to monitor");

    restore_signals(original_set);

    let res = registry.event_loop(&mut runner);

    // HANDSHAKE 2: Send "Stop" (Edge) to tell monitor to exit
    // If we're here, we are done with outputs.
    // Monitor might already be waiting.
    // We ignore error here as monitor might have died already.
    let _ = runner
        .backchannel
        .send_monitor_message(&MonitorMessage::Edge);
    debug!("runner(pty): sent stop edge to monitor");

    // restore
    if runner.term_raw
        && runner
            .pipe
            .left()
            .as_tty()
            .and_then(|tty| tty.tcgetpgrp())
            .is_ok_and(|pgrp| pgrp == runner.parent_pgrp)
    {
        runner.pipe.left_mut().restore(true)?;
    }

    match res {
        StopReason::Exit(status) => {
            let _ = runner.pipe.flush_left();
            Ok(status)
        }
        StopReason::Break(e) => Err(e),
    }
}

fn block_all_signals() -> Option<libc::sigset_t> {
    let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        libc::sigfillset(&raw mut set);
    }

    let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let res = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &raw const set, &raw mut old) };
    if res == -1 {
        None
    } else {
        Some(old)
    }
}

fn restore_signals(original: Option<libc::sigset_t>) {
    if let Some(set) = original {
        unsafe {
            libc::sigprocmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SimpleFileLogger, run_no_pty};
    use crate::orchestrator::{Orchestrator, PreExecContext, PreExecStep, Stage};
    use crate::pipe::io_logger_sealed::Sealed;
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
