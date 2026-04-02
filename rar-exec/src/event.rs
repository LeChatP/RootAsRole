use std::{
    ffi::c_short,
    fmt::Debug,
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
};

use libc::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, pollfd};

pub trait Process: Sized {
    type Event: Copy + Debug;
    type Break;
    type Exit;
    fn on_event(&mut self, event: Self::Event, registry: &mut EventRegistry<Self>);
}

enum Status<T: Process> {
    Continue,
    Stop(StopReason<T>),
}

impl<T: Process> Status<T> {
    const fn is_break(&self) -> bool {
        matches!(self, Self::Stop(StopReason::Break(_)))
    }

    fn take_stop(&mut self) -> Option<StopReason<T>> {
        let status = std::mem::replace(self, Self::Continue);
        match status {
            Self::Continue => None,
            Self::Stop(reason) => Some(reason),
        }
    }

    fn take_exit(&mut self) -> Option<T::Exit> {
        match self.take_stop()? {
            reason @ StopReason::Break(_) => {
                *self = Self::Stop(reason);
                None
            }
            StopReason::Exit(exit_reason) => Some(exit_reason),
        }
    }
}

pub enum StopReason<T: Process> {
    Break(T::Break),
    Exit(T::Exit),
}

#[derive(PartialEq, Eq, Hash, Ord, PartialOrd, Clone, Copy)]
struct EventId(usize);

pub struct EventHandle {
    id: EventId,
    should_poll: bool,
}

impl EventHandle {
    pub fn ignore<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        if self.should_poll
            && let Some(poll_fd) = registry.poll_fds.get_mut(self.id.0)
        {
            poll_fd.should_poll = false;
            self.should_poll = false;
        }
    }

    pub fn resume<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        if !self.should_poll
            && let Some(poll_fd) = registry.poll_fds.get_mut(self.id.0)
        {
            poll_fd.should_poll = true;
            self.should_poll = true;
        }
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.should_poll
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PollEvent {
    Readable,
    Writable,
}

struct PollFd<T: Process> {
    raw_fd: RawFd,
    event_flags: c_short,
    should_poll: bool,
    event: T::Event,
}

pub struct EventRegistry<T: Process> {
    poll_fds: Vec<PollFd<T>>,
    status: Status<T>,
}

impl<T: Process> Default for EventRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Process> EventRegistry<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            poll_fds: Vec::new(),
            status: Status::Continue,
        }
    }

    pub fn register_event<F: AsFd>(
        &mut self,
        fd: &F,
        poll_event: PollEvent,
        event_fn: impl Fn(PollEvent) -> T::Event,
    ) -> EventHandle {
        let id = EventId(self.poll_fds.len());

        self.poll_fds.push(PollFd {
            raw_fd: fd.as_fd().as_raw_fd(),
            event_flags: match poll_event {
                PollEvent::Readable => POLLIN,
                PollEvent::Writable => POLLOUT,
            },
            should_poll: true,
            event: event_fn(poll_event),
        });

        EventHandle {
            id,
            should_poll: true,
        }
    }

    fn poll(&self) -> io::Result<Vec<EventId>> {
        let (mut ids, mut fds): (Vec<EventId>, Vec<pollfd>) = self
            .poll_fds
            .iter()
            .enumerate()
            .filter_map(|(index, poll_fd)| {
                poll_fd.should_poll.then_some({
                    (
                        EventId(index),
                        pollfd {
                            fd: poll_fd.raw_fd,
                            events: poll_fd.event_flags,
                            revents: 0,
                        },
                    )
                })
            })
            .unzip();

        if ids.is_empty() {
            return Ok(ids);
        }

        // SAFETY: C compatible layout
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        for (i, fd) in fds.iter().enumerate().rev() {
            let io_events = fd.events & fd.revents;
            let terminal_events = fd.revents & (POLLERR | POLLHUP | POLLNVAL);
            if !((io_events & POLLIN != 0) || (io_events & POLLOUT != 0) || terminal_events != 0) {
                ids.remove(i);
            }
        }

        Ok(ids)
    }

    pub fn set_break(&mut self, reason: T::Break) {
        self.status = Status::Stop(StopReason::Break(reason));
    }

    pub fn set_exit(&mut self, reason: T::Exit) {
        self.status = Status::Stop(StopReason::Exit(reason));
    }

    pub const fn got_break(&self) -> bool {
        self.status.is_break()
    }

    #[allow(clippy::iter_with_drain)]
    /// # Panics
    /// Panics if the event handle is invalid
    pub fn event_loop(mut self, process: &mut T) -> StopReason<T> {
        let mut event_queue = Vec::with_capacity(self.poll_fds.len());

        loop {
            match self.poll() {
                Ok(ids) => {
                    for EventId(index) in ids {
                        let event = self.poll_fds[index].event;
                        event_queue.push(event);
                    }

                    for event in event_queue.drain(..) {
                        process.on_event(event, &mut self);

                        if let Some(reason) = self.status.take_exit() {
                            return StopReason::Exit(reason);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("unrecoverable poll error: {e}"),
            }

            if let Some(reason) = self.status.take_stop() {
                return reason;
            }
        }
    }
}
