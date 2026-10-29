/// Parts of the code below are Copyright (c) 2023, Conrad Kleinespel et al. And took from the sudo-rs project.
/// The sudo-rs project is licensed under the Apache License, Version 2.0 and MIT License.
///
/// This module contains code that was originally written by Conrad Kleinespel for the rpassword
/// crate. The crate is under Apache 2.0 licence.
///
/// See: <https://docs.rs/rpassword/latest/rpassword/>
///
/// Most code was replaced and so is no longer a derived work; work that we kept:
///
/// - the ``HiddenInput`` struct and implementation, with changes:
///   * replaced occurences of explicit 'i32' and '``c_int``' with ``RawFd``
///   * open the TTY ourselves to mitigate Linux CVE-2023-2002
/// - the general idea of a "``SafeString``" type that clears its memory
///   (although much more robust than in the original code)
///
/// The signals at the prompt follow sudo-rs 532ede4d ("Clear feedback on signals"), written
/// with nix, with two differences: a signal that the process ignores stays ignored, and the
/// prompt signals are blocked while the terminal gets its echo back, so that it gets it from
/// the background too. A signal stops the read itself (`read_unbuffered` does not read again
/// after EINTR), where sudo-rs polls the terminal.
///
use std::io::{self, Error, ErrorKind};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, mem};

use libc::{ECHO, ECHONL, TCSANOW, tcsetattr, termios};
use nix::sys::signal::{
    SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal, raise, sigaction,
};

use super::cutils::cerr;

use super::securemem::PamBuffer;

pub struct HiddenInput {
    tty: fs::File,
    term_orig: termios,
}

impl HiddenInput {
    #[cfg_attr(tarpaulin, ignore)]
    fn new() -> io::Result<Option<Self>> {
        // control ourselves that we are really talking to a TTY
        // mitigates: https://marc.info/?l=oss-security&m=168164424404224
        let Ok(tty) = fs::File::open("/dev/tty") else {
            // if we have nothing to show, we have nothing to hide
            return Ok(None);
        };
        let fd = tty.as_raw_fd();

        // Make two copies of the terminal settings. The first one will be modified
        // and the second one will act as a backup for when we want to set the
        // terminal back to its original state.
        let mut term = safe_tcgetattr(fd)?;
        let term_orig = safe_tcgetattr(fd)?;

        // Hide the password. This is what makes this function useful.
        term.c_lflag &= !ECHO;

        // But don't hide the NL character when the user hits ENTER.
        term.c_lflag |= ECHONL;

        // Save the settings for now.
        // SAFETY: we are passing tcsetattr a valid file descriptor and pointer-to-struct
        cerr(unsafe { tcsetattr(fd, TCSANOW, &raw const term) })?;

        Ok(Some(Self { tty, term_orig }))
    }
}

impl Drop for HiddenInput {
    #[cfg_attr(tarpaulin, ignore)]
    fn drop(&mut self) {
        // Set the mode back to normal and discard unread inputs
        // See GHSA-c978-wq47-pvvw.
        // SAFETY: we are passing tcsetattr a valid file descriptor and pointer-to-struct
        unsafe {
            libc::tcsetattr(
                self.tty.as_raw_fd(),
                libc::TCSAFLUSH,
                &raw const self.term_orig,
            );
        }
    }
}

#[cfg_attr(tarpaulin, ignore)]
fn safe_tcgetattr(fd: RawFd) -> io::Result<termios> {
    let mut term = mem::MaybeUninit::<termios>::uninit();
    // SAFETY: we are passing tcgetattr a pointer to valid memory
    cerr(unsafe { ::libc::tcgetattr(fd, term.as_mut_ptr()) })?;
    // SAFETY: if the previous call was a success, `tcgetattr` has initialized `term`
    Ok(unsafe { term.assume_init() })
}

const EOL: u8 = 0x0A;

/// Reads a password from the given file descriptor, one byte at a time into the buffer. A
/// signal stops the read (`ErrorKind::Interrupted`): `Read::bytes` would read again.
pub fn read_unbuffered(source: &mut (impl io::Read + ?Sized)) -> io::Result<PamBuffer> {
    let mut password = PamBuffer::default();
    let mut len = 0;
    // the byte after a full buffer: the end of the password, or one too many, which is refused
    let mut overflow = 0;

    loop {
        let byte = if len < password.len() {
            &mut password[len]
        } else {
            &mut overflow
        };
        if source.read(std::slice::from_mut(byte))? == 0 {
            break;
        }
        if *byte == EOL {
            *byte = 0;
            break;
        }
        if len == password.len() {
            return Err(Error::new(
                ErrorKind::OutOfMemory,
                "incorrect password attempt",
            ));
        }
        len += 1;
    }

    Ok(password)
}

/// The signals that end or stop dosr at the password prompt, those that end it first. They are
/// kept pending while the password is read, and acted on once the terminal has its echo back:
/// ^C does not leave the terminal without echo, and after ^Z and `fg` the echo is hidden again
/// before the rest of the password is typed.
const PROMPT_SIGNALS: [Signal; 8] = [
    Signal::SIGALRM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGTERM,
    Signal::SIGTSTP,
    Signal::SIGTTIN,
    Signal::SIGTTOU,
];

static PENDING: [AtomicBool; PROMPT_SIGNALS.len()] =
    [const { AtomicBool::new(false) }; PROMPT_SIGNALS.len()];

extern "C" fn keep_pending(signal: libc::c_int) {
    // no allocation, no lock: an atomic store only, which is async-signal-safe
    if let Ok(signal) = Signal::try_from(signal)
        && let Some(index) = PROMPT_SIGNALS.iter().position(|s| *s == signal)
    {
        PENDING[index].store(true, Ordering::SeqCst);
    }
}

/// The prompt signals blocked in this thread, until dropped.
struct BlockedSignals(Option<SigSet>);

impl BlockedSignals {
    fn block() -> Self {
        let signals: SigSet = PROMPT_SIGNALS.into_iter().collect();
        Self(signals.thread_swap_mask(SigmaskHow::SIG_BLOCK).ok())
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        if let Some(mask) = &self.0 {
            let _ = mask.thread_set_mask();
        }
    }
}

/// The prompt signals kept pending, until dropped: the dispositions of the process are given
/// back then. A signal that the process ignores stays ignored.
struct CaughtSignals(Vec<(Signal, SigAction)>);

impl CaughtSignals {
    fn catch() -> Self {
        // a signal sent while the handlers change waits, and goes to the final disposition
        let _blocked = BlockedSignals::block();
        // without SA_RESTART: the signal stops the read of the password
        let action = SigAction::new(
            SigHandler::Handler(keep_pending),
            SaFlags::empty(),
            SigSet::empty(),
        );
        let caught = PROMPT_SIGNALS
            .into_iter()
            .filter_map(|signal| {
                // SAFETY: the handler only stores into an atomic, which is async-signal-safe
                let previous = unsafe { sigaction(signal, &action) }.ok()?;
                if matches!(previous.handler(), SigHandler::SigIgn) {
                    // SAFETY: the disposition that the process had
                    let _ = unsafe { sigaction(signal, &previous) };
                    return None;
                }
                Some((signal, previous))
            })
            .collect();
        for pending in &PENDING {
            pending.store(false, Ordering::SeqCst);
        }
        Self(caught)
    }
}

impl Drop for CaughtSignals {
    fn drop(&mut self) {
        for (signal, previous) in &self.0 {
            // SAFETY: the disposition that the process had
            let _ = unsafe { sigaction(*signal, previous) };
        }
    }
}

/// The first prompt signal kept pending, in the order of `PROMPT_SIGNALS`; the others are
/// forgotten.
fn take_pending() -> Option<Signal> {
    let mut first = None;
    for (signal, pending) in PROMPT_SIGNALS.into_iter().zip(&PENDING) {
        if pending.swap(false, Ordering::SeqCst) && first.is_none() {
            first = Some(signal);
        }
    }
    first
}

const fn stops(signal: Signal) -> bool {
    matches!(signal, Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU)
}

/// End dosr by `signal`, as it would have ended without the prompt.
fn end_with(signal: Signal) -> ! {
    // SAFETY: SIG_DFL installs no handler
    let _ = unsafe { nix::sys::signal::signal(signal, SigHandler::SigDfl) };
    let _ = SigSet::from(signal).thread_unblock();
    let _ = raise(signal);
    // the signal did not end dosr: the status that a shell reports for it
    std::process::exit(128 + signal as i32)
}

/// Write something and immediately flush
fn write_unbuffered(sink: &mut impl io::Write, text: &str) -> io::Result<()> {
    sink.write_all(text.as_bytes())?;
    sink.flush()
}

/// A data structure representing either /dev/tty or /dev/stdin+stderr
pub enum Terminal<'a> {
    Tty(fs::File),
    StdIE(io::StdinLock<'a>, io::StderrLock<'a>),
}

impl Terminal<'_> {
    /// Open the current TTY for user communication
    #[cfg_attr(tarpaulin, ignore)]
    pub fn open_tty() -> io::Result<Self> {
        Ok(Terminal::Tty(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")?,
        ))
    }

    /// Open standard input and standard error for user communication
    pub fn open_stdie() -> Terminal<'static> {
        Terminal::StdIE(io::stdin().lock(), io::stderr().lock())
    }

    /// Writes `prompt` and reads input with TTY echo disabled. A prompt signal is acted on once
    /// the echo is back: ^C, SIGTERM, SIGHUP... end dosr by the same signal; ^Z stops it, and
    /// when it continues, the echo is hidden and the prompt written again.
    #[cfg_attr(tarpaulin, ignore)]
    pub fn read_password(&mut self, prompt: &str) -> io::Result<PamBuffer> {
        loop {
            let hidden = HiddenInput::new()?;
            // after the echo is hidden, so that the prompt shows again when dosr continues
            self.prompt(&prompt)?;
            let caught = CaughtSignals::catch();
            let password = read_unbuffered(self.source());
            let blocked = BlockedSignals::block();
            drop(caught);
            // the echo is back, from the background too: SIGTTOU is blocked
            drop(hidden);
            drop(blocked);
            match take_pending() {
                Some(signal) if stops(signal) => {
                    let _ = raise(signal);
                }
                Some(signal) => end_with(signal),
                None => return password,
            }
        }
    }

    /// Reads input with TTY echo enabled
    pub fn read_cleartext(&mut self) -> io::Result<PamBuffer> {
        read_unbuffered(&mut self.source())
    }

    /// Display information
    pub fn prompt(&mut self, text: &impl AsRef<str>) -> io::Result<()> {
        write_unbuffered(&mut self.sink(), text.as_ref())
    }

    // boilerplate reduction functions
    fn source(&mut self) -> &mut dyn io::Read {
        match self {
            Terminal::StdIE(x, _) => x,
            Terminal::Tty(x) => x,
        }
    }

    fn sink(&mut self) -> &mut dyn io::Write {
        match self {
            Terminal::StdIE(_, x) => x,
            Terminal::Tty(x) => x,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        BlockedSignals, CaughtSignals, Ordering, PENDING, PROMPT_SIGNALS, SaFlags, SigAction,
        SigHandler, SigSet, Signal, Terminal, raise, read_unbuffered, sigaction, stops,
        take_pending, write_unbuffered,
    };
    use std::io::{self, Read, Write};

    #[test]
    #[allow(clippy::string_lit_as_bytes)]
    fn miri_test_read() {
        let mut data = "password123\nhello world".as_bytes();
        let buf = read_unbuffered(&mut data).unwrap();
        // check that the \n is not part of input
        assert_eq!(
            buf.iter()
                .map(|&b| b as char)
                .take_while(|&x| x != '\0')
                .collect::<String>(),
            "password123"
        );
        // check that the \n is also consumed but the rest of the input is still there
        assert_eq!(std::str::from_utf8(data).unwrap(), "hello world");
    }

    #[test]
    fn miri_test_longpwd() {
        assert!(read_unbuffered(&mut "a".repeat(511).as_bytes()).is_ok());
        assert!(read_unbuffered(&mut "a".repeat(512).as_bytes()).is_err());
    }

    /// A source that gives `parts` one after the other, and stops with `ErrorKind::Interrupted`
    /// between them, as a read that a signal stops.
    struct Interrupted<'a> {
        parts: std::slice::Iter<'a, &'a [u8]>,
        current: &'a [u8],
    }

    impl Read for Interrupted<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.current.is_empty() {
                let Some(next) = self.parts.next() else {
                    return Ok(0);
                };
                self.current = next;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = buf.len().min(self.current.len());
            buf[..n].copy_from_slice(&self.current[..n]);
            self.current = &self.current[n..];
            Ok(n)
        }
    }

    // a signal stops the read: the prompt acts on it, where Read::bytes would read again
    #[test]
    fn miri_test_read_stops_on_a_signal() {
        let parts: &[&[u8]] = &[b"cd\n"];
        let mut source = Interrupted {
            parts: parts.iter(),
            current: b"ab",
        };
        let error = read_unbuffered(&mut source).err().map(|e| e.kind());
        assert_eq!(error, Some(io::ErrorKind::Interrupted));
    }

    #[test]
    fn miri_test_end_of_a_full_buffer() {
        let mut data = format!("{}\nnext", "a".repeat(511));
        let buf = read_unbuffered(&mut data.as_bytes()).unwrap();
        assert!(buf.iter().all(|&b| b == b'a'));
        data = "a".repeat(512) + "\n";
        assert!(read_unbuffered(&mut data.as_bytes()).is_err());
    }

    #[test]
    fn miri_test_write() {
        let mut data = Vec::new();
        write_unbuffered(&mut data, "prompt").unwrap();
        assert_eq!(std::str::from_utf8(&data).unwrap(), "prompt");
    }

    // Mock structure to simulate a file for testing Terminal::Tty variant
    struct MockFile {
        read_data: Vec<u8>,
        read_pos: usize,
        write_data: Vec<u8>,
    }

    impl MockFile {
        fn new(data: &str) -> Self {
            Self {
                read_data: data.as_bytes().to_vec(),
                read_pos: 0,
                write_data: Vec::new(),
            }
        }
    }

    impl Read for MockFile {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let available = self.read_data.len().saturating_sub(self.read_pos);
            let to_read = buf.len().min(available);

            if to_read > 0 {
                buf[..to_read]
                    .copy_from_slice(&self.read_data[self.read_pos..self.read_pos + to_read]);
                self.read_pos += to_read;
            }

            Ok(to_read)
        }
    }

    impl Write for MockFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // the prompt signals are process-wide: one test at a time changes them
    static SIGNALS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The disposition of `signal`, given back as it was.
    fn disposition(signal: Signal) -> SigHandler {
        let probe = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
        let _blocked = SigSet::from(signal).thread_block();
        // SAFETY: the disposition is given back at once, the signal is blocked meanwhile
        let previous = unsafe { sigaction(signal, &probe) }.unwrap();
        // SAFETY: the disposition that the process had
        unsafe { sigaction(signal, &previous) }.unwrap();
        let _ = SigSet::from(signal).thread_unblock();
        previous.handler()
    }

    // while the password is read, a prompt signal is only kept; the dispositions are given
    // back after it; a signal that ends dosr comes before one that stops it
    #[test]
    fn test_prompt_signals_are_kept_pending() {
        let _guard = SIGNALS.lock().unwrap();
        let before = disposition(Signal::SIGALRM);
        let caught = CaughtSignals::catch();
        raise(Signal::SIGTSTP).unwrap();
        raise(Signal::SIGALRM).unwrap();
        raise(Signal::SIGINT).unwrap();
        drop(caught);
        assert_eq!(take_pending(), Some(Signal::SIGALRM));
        assert_eq!(take_pending(), None, "the other signals are forgotten");
        assert!(matches!(
            (before, disposition(Signal::SIGALRM)),
            (SigHandler::SigDfl, SigHandler::SigDfl)
        ));

        let caught = CaughtSignals::catch();
        raise(Signal::SIGTSTP).unwrap();
        drop(caught);
        assert_eq!(take_pending(), Some(Signal::SIGTSTP));
        assert!(stops(Signal::SIGTSTP) && !stops(Signal::SIGINT));

        // a signal kept by an earlier prompt is not acted on at the next one
        PENDING[1].store(true, Ordering::SeqCst);
        drop(CaughtSignals::catch());
        assert_eq!(take_pending(), None);
    }

    // a signal that the caller ignores, as a command started with nohup, stays ignored
    #[test]
    fn test_an_ignored_signal_stays_ignored() {
        let _guard = SIGNALS.lock().unwrap();
        // SAFETY: SIG_IGN installs no handler
        let previous = unsafe { nix::sys::signal::signal(Signal::SIGHUP, SigHandler::SigIgn) };
        let caught = CaughtSignals::catch();
        assert!(matches!(disposition(Signal::SIGHUP), SigHandler::SigIgn));
        raise(Signal::SIGHUP).unwrap();
        drop(caught);
        assert_eq!(take_pending(), None);
        // SAFETY: the disposition that the process had
        unsafe { nix::sys::signal::signal(Signal::SIGHUP, previous.unwrap()) }.unwrap();
    }

    #[test]
    fn test_blocked_signals_are_unblocked_after() {
        let _guard = SIGNALS.lock().unwrap();
        let before = SigSet::thread_get_mask().unwrap();
        let blocked = BlockedSignals::block();
        let inside = SigSet::thread_get_mask().unwrap();
        assert!(
            PROMPT_SIGNALS
                .into_iter()
                .all(|signal| inside.contains(signal))
        );
        drop(blocked);
        assert_eq!(SigSet::thread_get_mask().unwrap(), before);
    }

    #[test]
    fn test_terminal_variant_matching() {
        // Test that we can match on Terminal variants
        let terminal = Terminal::open_stdie();

        match terminal {
            Terminal::StdIE(_, _) => {}
            Terminal::Tty(_) => {
                // Not expected for open_stdie
                panic!("Expected StdIE variant, got Tty");
            }
        }
    }
}
