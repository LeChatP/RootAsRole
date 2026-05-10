use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::event::{EventRegistry, PollEvent, Process};
use crate::orchestrator::{Orchestrator, PreExecContext};
use crate::pty::PtyFollower;
use crate::signal::{SignalInfo, SignalStream, register_signal_handler};
use crate::terminal::TerminalExt;
use libc::{SIGCHLD, SIGKILL};
use log::{debug, error, trace, warn};

pub mod backchannel;
use self::backchannel::{
    Backchannel, MONITOR_SIGNALS, MonitorMessage, ParentMessage, is_forward_signal_allowed,
};

pub struct MonitorClosure {
    command_pid: Option<libc::pid_t>,
    command_pgrp: libc::pid_t,
    monitor_pgrp: libc::pid_t,
    pty_follower: PtyFollower,
    signal_stream: &'static SignalStream,
    backchannel: Backchannel,
    err_reader: std::os::unix::net::UnixStream,
    err_handle: crate::event::EventHandle,
}

#[derive(Clone, Copy, Debug)]
pub enum MonitorEvent {
    Signal,
    Backchannel,
    ErrPipe,
}

impl Process for MonitorClosure {
    type Event = MonitorEvent;
    type Break = io::Error;
    type Exit = ();

    fn on_event(&mut self, event: Self::Event, registry: &mut EventRegistry<Self>) {
        match event {
            MonitorEvent::ErrPipe => {
                use std::io::Read;
                let mut buf = [0u8; 1024];
                match self.err_reader.read(&mut buf) {
                    Ok(0) => {
                        // EOF: stop polling this FD to avoid busy loop
                        trace!("monitor: err pipe EOF");
                        self.err_handle.ignore(registry);
                    }
                    Ok(n) => {
                        let err_msg = String::from_utf8_lossy(&buf[..n]).to_string();
                        warn!("monitor: exec error: {err_msg}");
                        if let Err(e) = self
                            .backchannel
                            .send_parent_message(&ParentMessage::Error(err_msg.clone()))
                        {
                            // Backchannel failure suggests parent is gone; log and continue
                            error!("Failed to send error message to parent: {e}");
                        }

                        if let Some(pid) = self.command_pid {
                            let mut status = 0;
                            unsafe { libc::waitpid(pid, &raw mut status, 0) };
                            let _ = self
                                .backchannel
                                .send_parent_message(&ParentMessage::ExitStatus(status));
                            self.command_pid = None;
                        }

                        registry
                            .set_break(io::Error::other(format!("Child process error: {err_msg}")));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => registry.set_break(e),
                }
            }
            MonitorEvent::Signal => loop {
                match self.signal_stream.recv() {
                    Ok(info) => self.handle_signal(info, registry),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        warn!("monitor: signal recv error: {e}");
                        registry.set_break(e);
                        break;
                    }
                }
            },
            MonitorEvent::Backchannel => {
                trace!("monitor: backchannel readable");
                match self.backchannel.recv_monitor_message() {
                    Ok(MonitorMessage::Signal(sig)) => {
                        debug!("monitor: signal from parent {sig}");
                        if is_forward_signal_allowed(sig) {
                            if let Some(pid) = self.command_pid {
                                if sig == libc::SIGALRM {
                                    unsafe { libc::kill(pid, libc::SIGKILL) };
                                } else {
                                    unsafe { libc::kill(pid, sig) };
                                }
                            }
                        } else {
                            let _ = self.backchannel.send_parent_message(&ParentMessage::Error(
                                format!("Rejected disallowed signal value: {sig}"),
                            ));
                        }
                    }
                    Ok(MonitorMessage::Edge) => {
                        if self.command_pid.is_none() {
                            debug!("monitor: stop edge received after command exit");
                            registry.set_break(io::Error::from_raw_os_error(0));
                        }
                    }
                    //Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => { },
                    Err(e) => {
                        registry.set_break(e);
                    }
                }
            }
        }
    }
}

impl MonitorClosure {
    fn handle_signal(&mut self, info: SignalInfo, registry: &mut EventRegistry<Self>) {
        debug!("monitor: got signal {} from pid {}", info.signal, info.pid);
        if info.signal == SIGCHLD {
            if let Some(pid) = self.command_pid {
                let mut status = 0;
                let res =
                    unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG | libc::WUNTRACED) };
                if res > 0 {
                    if libc::WIFSTOPPED(status) {
                        warn!("monitor: command stopped with {}", libc::WSTOPSIG(status));
                        let _ =
                            self.backchannel
                                .send_parent_message(&ParentMessage::Error(format!(
                                    "Command stopped with signal {}",
                                    libc::WSTOPSIG(status)
                                )));
                        return;
                    }

                    self.command_pid = None;
                    debug!("monitor: command exited with status {status}");
                    let _ = self
                        .backchannel
                        .send_parent_message(&ParentMessage::ExitStatus(status));
                    registry.set_break(io::Error::from_raw_os_error(0));
                }
            }
            return;
        }

        if let Some(pid) = self.command_pid {
            if info.pid > 0 && is_self_terminating(info.pid, pid, self.command_pgrp) {
                trace!("monitor: ignoring self-terminating signal {}", info.signal);
                return;
            }

            if is_forward_signal_allowed(info.signal) {
                debug!("monitor: forwarding signal {}", info.signal);
                if info.signal == libc::SIGALRM {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                } else {
                    unsafe { libc::kill(pid, info.signal) };
                }
            }
        }
    }
}

fn is_self_terminating(
    signaler_pid: libc::pid_t,
    command_pid: libc::pid_t,
    command_pgrp: libc::pid_t,
) -> bool {
    if signaler_pid <= 0 {
        return false;
    }

    if signaler_pid == command_pid {
        return true;
    }

    let signaler_pgrp = unsafe { libc::getpgid(signaler_pid) };
    signaler_pgrp == command_pgrp
}

#[allow(clippy::too_many_lines)]
/// # Errors
/// Returns an error if any system call fails during the monitor process execution.
pub fn exec_monitor_process(
    pty_follower: PtyFollower,
    mut command: Command,
    orchestrator: Orchestrator,
    mut backchannel: Backchannel,
    original_set: Option<&libc::sigset_t>,
    foreground: bool,
) -> io::Result<()> {
    debug!("monitor: starting (foreground={foreground})");
    unsafe {
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error());
    }

    pty_follower.as_tty()?.make_controlling_terminal()?;
    debug!("monitor: controlling terminal set");

    let f_fd = pty_follower.as_fd().as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            let ctx = PreExecContext::with_tty(f_fd);
            orchestrator.run(&ctx)
        });
    }

    backchannel.set_nonblocking(false)?;
    loop {
        match backchannel.recv_monitor_message() {
            Ok(MonitorMessage::Edge) => break,
            Ok(msg) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unexpected message before exec handshake: {msg:?}"),
                ));
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(e),
        }
    }
    debug!("monitor: received start edge");
    backchannel.set_nonblocking(true)?;

    let (err_reader, mut err_writer) = std::os::unix::net::UnixStream::pair()?;

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        drop(err_reader); // Close reader end in child

        // Restore default signal handlers
        for sig in 1..32 {
            unsafe { libc::signal(sig, libc::SIG_DFL) };
        }

        // Restore signal mask
        let set: libc::sigset_t = original_set.map_or_else(
            || {
                let mut tmp = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                unsafe { libc::sigemptyset(&raw mut tmp) };
                tmp
            },
            |s| *s,
        );

        unsafe {
            libc::sigprocmask(libc::SIG_SETMASK, &raw const set, std::ptr::null_mut());
        }

        let _ = unsafe { libc::setpgid(0, 0) };
        let cmd_pid = unsafe { libc::getpid() };

        if foreground {
            debug!("monitor: waiting for foreground pgrp switch");
            let mut ready = false;
            for _ in 0..10_000 {
                let pgrp = unsafe { libc::tcgetpgrp(pty_follower.as_fd().as_raw_fd()) };
                if pgrp == cmd_pid {
                    ready = true;
                    break;
                }
                std::thread::yield_now();
            }
            if !ready {
                warn!("monitor: foreground pgrp switch timeout, continuing exec");
            }
        }

        let err = command.exec();

        // If we are here, exec failed.
        let err_msg = format!("Failed to exec: {err}");
        let _ = err_writer.write_all(err_msg.as_bytes());

        unsafe { libc::_exit(1) };
    }

    // PARENT (The Monitor)
    drop(err_writer); // Close writer end in parent

    err_reader.set_nonblocking(true)?;

    let _ = unsafe { libc::setpgid(pid, pid) };
    if foreground {
        let res = unsafe { libc::tcsetpgrp(pty_follower.as_fd().as_raw_fd(), pid) };
        if res == -1 {
            warn!("monitor: tcsetpgrp failed: {}", io::Error::last_os_error());
        } else {
            debug!("monitor: set foreground pgrp to {pid}");
        }
    }
    debug!("monitor: command pid {pid}");

    // Send PID to Runner
    let _ = backchannel.send_parent_message(&ParentMessage::CommandPid(pid));
    debug!("monitor: sent command pid to parent");

    let mut registry = EventRegistry::new();

    let err_handle =
        registry.register_event(&err_reader, PollEvent::Readable, |_| MonitorEvent::ErrPipe);

    let signal_stream = SignalStream::init()?;
    for &sig in MONITOR_SIGNALS {
        register_signal_handler(sig)?;
    }
    debug!("monitor: signal handlers installed");

    if let Some(set) = original_set {
        unsafe {
            libc::sigprocmask(libc::SIG_SETMASK, set, std::ptr::null_mut());
        }
        debug!("monitor: signal mask restored");
    }
    registry.register_event(signal_stream, PollEvent::Readable, |_| MonitorEvent::Signal);
    registry.register_event(&backchannel, PollEvent::Readable, |_| {
        MonitorEvent::Backchannel
    });

    let mut monitor = MonitorClosure {
        command_pid: Some(pid),
        command_pgrp: pid,
        monitor_pgrp: unsafe { libc::getpgrp() },
        pty_follower, // Keep it alive
        signal_stream,
        backchannel,
        err_reader,
        err_handle,
    };

    // Monitor Loop
    let _ = registry.event_loop(&mut monitor);
    debug!("monitor: event loop exited");

    monitor.backchannel.set_nonblocking(false)?; // Blocking wait
    loop {
        match monitor.backchannel.recv_monitor_message() {
            Ok(MonitorMessage::Edge) => break,
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break, // Parent closed
            Err(_e) => break,                                                // Error
        }
    }
    debug!("monitor: received stop edge or backchannel closed");

    let _ = unsafe {
        libc::tcsetpgrp(
            monitor.pty_follower.as_fd().as_raw_fd(),
            monitor.monitor_pgrp,
        )
    };

    // Cleanup
    if let Some(pid) = monitor.command_pid {
        unsafe { libc::kill(pid, SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
    }

    Ok(())
}
