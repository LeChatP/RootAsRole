use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::event::{EventRegistry, PollEvent, Process};
use crate::orchestrator::{Orchestrator, PreExecContext};
use crate::pty::PtyFollower;
use crate::signal::{SignalStream, register_signal_handler};
use crate::terminal::TerminalExt;
use libc::{SIGCHLD, SIGKILL};

pub mod backchannel;
use self::backchannel::{
    Backchannel, MONITOR_SIGNALS, MonitorMessage, ParentMessage, is_forward_signal_allowed,
};

pub struct MonitorClosure {
    command_pid: Option<u32>,
    pty_follower: PtyFollower,
    signal_stream: &'static SignalStream,
    backchannel: Backchannel,
    err_reader: std::os::unix::net::UnixStream,
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
                    Ok(0) => {} // EOF, no error
                    Ok(n) => {
                        let err_msg = String::from_utf8_lossy(&buf[..n]).to_string();
                        let _ = self
                            .backchannel
                            .send_parent_message(&ParentMessage::Error(err_msg));

                        if let Some(pid) = self.command_pid {
                            let mut status = 0;
                            unsafe { libc::waitpid(pid.cast_signed(), &raw mut status, 0) };
                            let _ = self
                                .backchannel
                                .send_parent_message(&ParentMessage::ExitStatus(status));
                            self.command_pid = None;
                        }

                        registry.set_break(io::Error::from_raw_os_error(0));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => registry.set_break(e),
                }
            }
            MonitorEvent::Signal => loop {
                match self.signal_stream.recv() {
                    Ok(info) => self.handle_signal(info.signal, registry),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        registry.set_break(e);
                        break;
                    }
                }
            },
            MonitorEvent::Backchannel => {
                loop {
                    match self.backchannel.recv_monitor_message() {
                        Ok(MonitorMessage::Signal(sig)) => {
                            if is_forward_signal_allowed(sig) {
                                if let Some(pid) = self.command_pid {
                                    unsafe { libc::kill(pid.cast_signed(), sig) };
                                }
                            } else {
                                let _ =
                                    self.backchannel.send_parent_message(&ParentMessage::Error(
                                        format!("Rejected disallowed signal value: {sig}"),
                                    ));
                            }
                        }
                        Ok(MonitorMessage::Edge) => {
                            // unexpected.
                            registry.set_break(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Unexpected Edge message from parent".to_string(),
                            ));
                            break;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            registry.set_break(e);
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl MonitorClosure {
    fn handle_signal(&mut self, signal: libc::c_int, registry: &mut EventRegistry<Self>) {
        if signal == SIGCHLD {
            if let Some(pid) = self.command_pid {
                let mut status = 0;
                let res =
                    unsafe { libc::waitpid(pid.cast_signed(), &raw mut status, libc::WNOHANG) };
                if res > 0 {
                    self.command_pid = None;
                    let _ = self
                        .backchannel
                        .send_parent_message(&ParentMessage::ExitStatus(status));
                    // Exit monitor loop naturally
                    registry.set_break(io::Error::from_raw_os_error(0));
                }
            }
        } else if is_forward_signal_allowed(signal)
            && let Some(pid) = self.command_pid
        {
            unsafe { libc::kill(pid.cast_signed(), signal) };
        }
    }
}

/// # Errors
/// Returns an error if any system call fails during the monitor process execution.
pub fn exec_monitor_process(
    pty_follower: PtyFollower,
    mut command: Command,
    orchestrator: Orchestrator,
    mut backchannel: Backchannel,
    original_set: Option<&libc::sigset_t>,
) -> io::Result<()> {
    if unsafe { libc::setsid() } == -1 {
        return Err(io::Error::last_os_error());
    }

    pty_follower.as_tty()?.make_controlling_terminal()?;

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

        while unsafe { libc::tcgetpgrp(pty_follower.as_fd().as_raw_fd()) } != cmd_pid {
            std::thread::yield_now();
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
    let _ = unsafe { libc::tcsetpgrp(pty_follower.as_fd().as_raw_fd(), pid) };

    // Send PID to Runner
    let _ = backchannel.send_parent_message(&ParentMessage::CommandPid(pid));

    let mut registry = EventRegistry::new();
    let signal_stream = SignalStream::init()?;
    for &sig in MONITOR_SIGNALS {
        register_signal_handler(sig)?;
    }
    registry.register_event(signal_stream, PollEvent::Readable, |_| MonitorEvent::Signal);
    registry.register_event(&backchannel, PollEvent::Readable, |_| {
        MonitorEvent::Backchannel
    });
    registry.register_event(&err_reader, PollEvent::Readable, |_| MonitorEvent::ErrPipe);

    let mut monitor = MonitorClosure {
        command_pid: Some(pid.cast_unsigned()),
        pty_follower, // Keep it alive
        signal_stream,
        backchannel,
        err_reader,
    };

    // Monitor Loop
    let _ = registry.event_loop(&mut monitor);

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

    let monitor_pgrp = unsafe { libc::getpgrp() };
    let _ = unsafe { libc::tcsetpgrp(monitor.pty_follower.as_fd().as_raw_fd(), monitor_pgrp) };

    // Cleanup
    if let Some(pid) = monitor.command_pid {
        unsafe { libc::kill(pid.cast_signed(), SIGKILL) };
        let mut status = 0;
        unsafe { libc::waitpid(pid.cast_signed(), &raw mut status, 0) };
    }

    Ok(())
}
