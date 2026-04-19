use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    os::fd::AsFd,
};

use super::event::{EventHandle, EventRegistry, PollEvent, Process};

use ringbuf::HeapRb;
use ringbuf::traits::{Consumer, Observer, Producer, Split};

pub const BUFFER_LEN: usize = 8 * 1024;

pub trait IoLogger {
    fn log_input(&mut self, data: &[u8]);
    fn log_output(&mut self, data: &[u8]);
}

// A pipe able to stream data bidirectionally between two read-write types.
pub struct Pipe<L, R> {
    left: L,
    right: R,
    buffer_lr: Buffer<L, R>,
    buffer_rl: Buffer<R, L>,
    background: bool,
    logger: Option<Box<dyn IoLogger>>,
}

impl<L: Read + Write + AsFd, R: Read + Write + AsFd> Pipe<L, R> {
    // new pipe
    pub fn new<T: Process>(
        left: L,
        right: R,
        registry: &mut EventRegistry<T>,
        f_left: fn(PollEvent) -> T::Event,
        f_right: fn(PollEvent) -> T::Event,
        logger: Option<Box<dyn IoLogger>>,
    ) -> Self {
        Self {
            buffer_lr: Buffer::new(
                registry.register_event(&left, PollEvent::Readable, f_left),
                registry.register_event(&right, PollEvent::Writable, f_right),
                registry,
            ),
            buffer_rl: Buffer::new(
                registry.register_event(&right, PollEvent::Readable, f_right),
                registry.register_event(&left, PollEvent::Writable, f_left),
                registry,
            ),
            left,
            right,
            background: false,
            logger,
        }
    }

    pub const fn left(&self) -> &L {
        &self.left
    }

    pub const fn left_mut(&mut self) -> &mut L {
        &mut self.left
    }

    pub const fn right(&self) -> &R {
        &self.right
    }

    pub fn ignore_events<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        self.buffer_lr.read_handle.ignore(registry);
        self.buffer_lr.write_handle.ignore(registry);
        self.buffer_rl.read_handle.ignore(registry);
        self.buffer_rl.write_handle.ignore(registry);
    }

    pub fn disable_input<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        self.buffer_lr.read_handle.ignore(registry);
        self.background = true;
    }

    pub fn resume_events<T: Process>(&mut self, registry: &mut EventRegistry<T>) {
        if !self.background {
            self.buffer_lr.read_handle.resume(registry);
        }
        self.buffer_lr.write_handle.resume(registry);
        self.buffer_rl.read_handle.resume(registry);
        self.buffer_rl.write_handle.resume(registry);
    }

    /// # Errors
    /// Returns an error if reading from or writing to the pipes fails, or if logging fails.
    pub fn on_left_event<T: Process>(
        &mut self,
        poll_event: PollEvent,
        registry: &mut EventRegistry<T>,
    ) -> io::Result<()> {
        match poll_event {
            PollEvent::Readable => {
                let bytes_read = self.buffer_lr.read(&mut self.left, registry)?;
                if bytes_read == 0 {
                    self.buffer_lr.read_handle.ignore(registry);
                } else if let Some(logger) = &mut self.logger {
                    let (s1, s2) = self.buffer_lr.get_last_n_bytes(bytes_read);
                    if !s1.is_empty() {
                        logger.log_input(s1);
                    }
                    if !s2.is_empty() {
                        logger.log_input(s2);
                    }
                }
                Ok(())
            }
            PollEvent::Writable => {
                if self.buffer_rl.write(&mut self.left, registry)? {
                    self.buffer_rl.read_handle.resume(registry);
                }
                Ok(())
            }
        }
    }

    /// # Errors
    /// Returns an error if reading from or writing to the pipes fails, or if logging fails.
    pub fn on_right_event<T: Process>(
        &mut self,
        poll_event: PollEvent,
        registry: &mut EventRegistry<T>,
    ) -> io::Result<()> {
        match poll_event {
            PollEvent::Readable => {
                let bytes_read = self.buffer_rl.read(&mut self.right, registry)?;
                if bytes_read == 0 {
                    self.buffer_rl.read_handle.ignore(registry);
                } else if let Some(logger) = &mut self.logger {
                    let (s1, s2) = self.buffer_rl.get_last_n_bytes(bytes_read);
                    if !s1.is_empty() {
                        logger.log_output(s1);
                    }
                    if !s2.is_empty() {
                        logger.log_output(s2);
                    }
                }
                Ok(())
            }
            PollEvent::Writable => {
                match self.buffer_lr.write(&mut self.right, registry) {
                    Ok(did_write) => {
                        if did_write && !self.background {
                            self.buffer_lr.read_handle.resume(registry);
                        }
                        Ok(())
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::BrokenPipe
                            || e.kind() == io::ErrorKind::UnexpectedEof =>
                    {
                        // PTY closed on write side; gracefully ignore and let event loop handle closure
                        self.buffer_lr.read_handle.ignore(registry);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// # Errors
    /// Returns an error if writing to the left pipe fails, or if logging fails.
    pub fn flush_left(&mut self) -> io::Result<()> {
        let buffer = &mut self.buffer_rl;
        let source = &mut self.right;
        let sink = &mut self.left;

        if let Some(res) = buffer.consumer.write_into(sink, None) {
            res?;
        }

        if buffer.write_handle.is_active() {
            let mut buf = [0u8; BUFFER_LEN];
            loop {
                match source.read(&mut buf) {
                    Ok(read_bytes) => {
                        if let Some(logger) = &mut self.logger {
                            logger.log_output(&buf[..read_bytes]);
                        }
                        sink.write_all(&buf[..read_bytes])?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        sink.flush()
    }
}

type RingBufferProducer = <HeapRb<u8> as Split>::Prod;
type RingBufferConsumer = <HeapRb<u8> as Split>::Cons;

struct Buffer<R, W> {
    producer: RingBufferProducer,
    consumer: RingBufferConsumer,
    read_handle: EventHandle,
    write_handle: EventHandle,
    marker: PhantomData<(R, W)>,
}

impl<R: Read, W: Write> Buffer<R, W> {
    fn new<T: Process>(
        read_handle: EventHandle,
        mut write_handle: EventHandle,
        registry: &mut EventRegistry<T>,
    ) -> Self {
        write_handle.ignore(registry);

        let (producer, consumer) = HeapRb::<u8>::new(BUFFER_LEN).split();

        Self {
            producer,
            consumer,
            read_handle,
            write_handle,
            marker: PhantomData,
        }
    }

    fn read<T: Process>(
        &mut self,
        read: &mut R,
        registry: &mut EventRegistry<T>,
    ) -> io::Result<usize> {
        if self.producer.is_full() {
            self.read_handle.ignore(registry);
            return Ok(0);
        }

        let was_empty = self.producer.is_empty();

        let inserted_len = match self.producer.read_from(read, None) {
            Some(res) => res?,
            None => 0,
        };

        if was_empty && inserted_len > 0 {
            // buffer has data, resume write
            self.write_handle.resume(registry);
        }

        Ok(inserted_len)
    }

    fn write<T: Process>(
        &mut self,
        write: &mut W,
        registry: &mut EventRegistry<T>,
    ) -> io::Result<bool> {
        let was_full = self.producer.is_full();

        let removed_len = if let Some(res) = self.consumer.write_into(write, None) {
            res?
        } else {
            // empty buffer, ignore write
            self.write_handle.ignore(registry);
            return Ok(false);
        };

        if was_full && removed_len > 0 {
            // space available, resume read
            self.read_handle.resume(registry);
        }

        // buffer drained, ignore write
        if self.consumer.is_empty() {
            self.write_handle.ignore(registry);
        } else {
            // data remains, ensure write active
            self.write_handle.resume(registry);
        }

        Ok(removed_len > 0)
    }

    pub fn get_last_n_bytes(&self, n: usize) -> (&[u8], &[u8]) {
        if n == 0 {
            return (&[], &[]);
        }

        // last n bytes
        // (older, newer)
        let (s1, s2) = self.consumer.as_slices();
        let len = s1.len() + s2.len();

        if len == 0 {
            return (&[], &[]);
        }
        let n = std::cmp::min(n, len);

        // [len - n, len)
        if n <= s2.len() {
            // all in s2
            (&s2[s2.len() - n..], &[])
        } else {
            // s2 + s1
            let remainder = n - s2.len();
            (&s1[s1.len() - remainder..], s2)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event::{EventRegistry, PollEvent, Process};
    use crate::pipe::{IoLogger, Pipe};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Debug, Copy, Clone)]
    enum TestEvent {
        PipeLeft(PollEvent),
        PipeRight(PollEvent),
        RemoteReadable,
    }

    struct MockLogger {
        input_log: Arc<Mutex<Vec<u8>>>,
        output_log: Arc<Mutex<Vec<u8>>>,
    }

    impl IoLogger for MockLogger {
        fn log_input(&mut self, data: &[u8]) {
            self.input_log.lock().unwrap().extend_from_slice(data);
        }

        fn log_output(&mut self, data: &[u8]) {
            self.output_log.lock().unwrap().extend_from_slice(data);
        }
    }

    struct TestProcess {
        pipe: Option<Pipe<UnixStream, UnixStream>>,
        l_remote: Option<UnixStream>,
        r_remote: Option<UnixStream>,

        received_data_at_r: Vec<u8>,
        received_data_at_l: Vec<u8>,

        expected_data_at_r: usize,
        expected_data_at_l: usize,
    }

    impl Process for TestProcess {
        type Event = TestEvent;
        type Break = ();
        type Exit = ();

        fn on_event(&mut self, event: Self::Event, registry: &mut EventRegistry<Self>) {
            match event {
                TestEvent::PipeLeft(e) => {
                    if let Some(pipe) = &mut self.pipe {
                        pipe.on_left_event(e, registry).unwrap();
                    }
                }
                TestEvent::PipeRight(e) => {
                    if let Some(pipe) = &mut self.pipe {
                        pipe.on_right_event(e, registry).unwrap();
                    }
                }
                TestEvent::RemoteReadable => {
                    if let Some(remote) = &mut self.r_remote {
                        let mut buf = [0u8; 1024];
                        loop {
                            match remote.read(&mut buf) {
                                Ok(n) if n > 0 => {
                                    self.received_data_at_r.extend_from_slice(&buf[..n]);
                                }
                                _ => break,
                            }
                        }
                    }

                    if let Some(remote) = &mut self.l_remote {
                        let mut buf = [0u8; 1024];
                        loop {
                            match remote.read(&mut buf) {
                                Ok(n) if n > 0 => {
                                    self.received_data_at_l.extend_from_slice(&buf[..n]);
                                }
                                _ => break,
                            }
                        }
                    }

                    if self.received_data_at_r.len() >= self.expected_data_at_r
                        && self.received_data_at_l.len() >= self.expected_data_at_l
                    {
                        registry.set_break(());
                    }
                }
            }
        }
    }

    #[test]
    fn test_pipe_flow_left_to_right() {
        let (l_local, l_remote) = UnixStream::pair().unwrap();
        let (r_local, r_remote) = UnixStream::pair().unwrap();

        l_remote.set_nonblocking(true).unwrap();
        r_remote.set_nonblocking(true).unwrap();

        let input_log = Arc::new(Mutex::new(Vec::new()));
        let output_log = Arc::new(Mutex::new(Vec::new()));

        let logger = MockLogger {
            input_log: input_log.clone(),
            output_log: output_log.clone(),
        };

        let mut registry = EventRegistry::<TestProcess>::new();

        let pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            Some(Box::new(logger)),
        );

        registry.register_event(&r_remote, PollEvent::Readable, |_| {
            TestEvent::RemoteReadable
        });

        let data_to_send = b"Hello from Left";
        let mut process = TestProcess {
            pipe: Some(pipe),
            l_remote: Some(l_remote),
            r_remote: Some(r_remote),
            received_data_at_r: Vec::new(),
            received_data_at_l: Vec::new(),
            expected_data_at_r: data_to_send.len(),
            expected_data_at_l: 0,
        };

        process
            .l_remote
            .as_mut()
            .unwrap()
            .write_all(data_to_send)
            .unwrap();

        registry.event_loop(&mut process);

        assert_eq!(process.received_data_at_r, data_to_send);
        assert_eq!(process.received_data_at_l.len(), 0);

        assert_eq!(*input_log.lock().unwrap(), data_to_send);
        assert!(output_log.lock().unwrap().is_empty());
    }

    #[test]
    fn test_pipe_flow_right_to_left() {
        let (l_local, l_remote) = UnixStream::pair().unwrap();
        let (r_local, r_remote) = UnixStream::pair().unwrap();

        l_remote.set_nonblocking(true).unwrap();
        r_remote.set_nonblocking(true).unwrap();

        let input_log = Arc::new(Mutex::new(Vec::new()));
        let output_log = Arc::new(Mutex::new(Vec::new()));

        let logger = MockLogger {
            input_log: input_log.clone(),
            output_log: output_log.clone(),
        };

        let mut registry = EventRegistry::<TestProcess>::new();

        let pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            Some(Box::new(logger)),
        );

        registry.register_event(&l_remote, PollEvent::Readable, |_| {
            TestEvent::RemoteReadable
        });

        let data_to_send = b"Hello from Right";
        let mut process = TestProcess {
            pipe: Some(pipe),
            l_remote: Some(l_remote),
            r_remote: Some(r_remote),
            received_data_at_r: Vec::new(),
            received_data_at_l: Vec::new(),
            expected_data_at_r: 0,
            expected_data_at_l: data_to_send.len(),
        };

        process
            .r_remote
            .as_mut()
            .unwrap()
            .write_all(data_to_send)
            .unwrap();

        registry.event_loop(&mut process);

        assert_eq!(process.received_data_at_l, data_to_send);

        assert_eq!(*output_log.lock().unwrap(), data_to_send);
        assert!(input_log.lock().unwrap().is_empty());
    }

    #[test]
    fn test_bidirectional_flow() {
        let (l_local, l_remote) = UnixStream::pair().unwrap();
        let (r_local, r_remote) = UnixStream::pair().unwrap();

        l_remote.set_nonblocking(true).unwrap();
        r_remote.set_nonblocking(true).unwrap();

        let mut registry = EventRegistry::<TestProcess>::new();

        let pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            None,
        );

        registry.register_event(&l_remote, PollEvent::Readable, |_| {
            TestEvent::RemoteReadable
        });
        registry.register_event(&r_remote, PollEvent::Readable, |_| {
            TestEvent::RemoteReadable
        });

        let data_l2r = b"LeftToRight";
        let data_r2l = b"RightToLeft";

        let mut process = TestProcess {
            pipe: Some(pipe),
            l_remote: Some(l_remote),
            r_remote: Some(r_remote),
            received_data_at_r: Vec::new(),
            received_data_at_l: Vec::new(),
            expected_data_at_r: data_l2r.len(),
            expected_data_at_l: data_r2l.len(),
        };

        process
            .l_remote
            .as_mut()
            .unwrap()
            .write_all(data_l2r)
            .unwrap();
        process
            .r_remote
            .as_mut()
            .unwrap()
            .write_all(data_r2l)
            .unwrap();

        registry.event_loop(&mut process);

        assert_eq!(process.received_data_at_r, data_l2r);
        assert_eq!(process.received_data_at_l, data_r2l);
    }

    #[test]
    fn test_pipe_flush_left() {
        let (l_local, l_remote) = UnixStream::pair().unwrap();
        let (r_local, mut r_remote) = UnixStream::pair().unwrap();

        l_local.set_nonblocking(true).unwrap();
        r_local.set_nonblocking(true).unwrap();

        let mut registry = EventRegistry::<TestProcess>::new();

        let mut pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            None,
        );

        let data = b"FlushData";
        r_remote.write_all(data).unwrap();

        pipe.on_right_event(PollEvent::Readable, &mut registry)
            .unwrap();

        pipe.flush_left().unwrap();

        let mut buf = [0u8; 1024];
        let mut l_remote_clone = l_remote.try_clone().unwrap();

        let n = l_remote_clone.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], data);
    }

    #[test]
    fn test_large_transfer() {
        let (l_local, mut l_remote) = UnixStream::pair().unwrap();
        let (r_local, r_remote) = UnixStream::pair().unwrap();

        r_remote.set_nonblocking(true).unwrap();

        let mut registry = EventRegistry::<TestProcess>::new();

        let pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            None,
        );

        registry.register_event(&r_remote, PollEvent::Readable, |_| {
            TestEvent::RemoteReadable
        });

        let data_len = 20 * 1024;
        #[allow(clippy::cast_possible_truncation)]
        let data_to_send: Vec<u8> = (0..data_len).map(|i| (i % 255) as u8).collect();
        let data_to_send_clone = data_to_send.clone();

        // Spawn writer thread
        thread::spawn(move || {
            l_remote.write_all(&data_to_send_clone).unwrap();
        });

        let mut process = TestProcess {
            pipe: Some(pipe),
            l_remote: None,
            r_remote: Some(r_remote),
            received_data_at_r: Vec::with_capacity(data_len),
            received_data_at_l: Vec::new(),
            expected_data_at_r: data_len,
            expected_data_at_l: 0,
        };

        registry.event_loop(&mut process);

        assert_eq!(process.received_data_at_r.len(), data_len);
        assert_eq!(process.received_data_at_r, data_to_send);
    }

    #[test]
    fn test_carriage_return_skipping() {
        let (l_local, mut l_remote) = UnixStream::pair().unwrap();
        let (r_local, r_remote) = UnixStream::pair().unwrap();

        l_remote.set_nonblocking(true).unwrap();
        r_remote.set_nonblocking(true).unwrap();

        let mut registry = EventRegistry::<TestProcess>::new();

        let pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            None,
        );

        registry.register_event(&r_remote, PollEvent::Readable, |_| {
            TestEvent::RemoteReadable
        });

        // We only expect things from l_remote to reach r_remote in this setup
        let data_to_send = b"Line 1\r\nLine 2\r\nLine 3\r\n";

        let mut process = TestProcess {
            pipe: Some(pipe),
            l_remote: Some(l_remote.try_clone().unwrap()),
            r_remote: Some(r_remote),
            received_data_at_r: Vec::new(),
            received_data_at_l: Vec::new(),
            expected_data_at_r: data_to_send.len(),
            expected_data_at_l: 0,
        };

        l_remote.write_all(data_to_send).unwrap();

        registry.event_loop(&mut process);

        assert_eq!(
            process.received_data_at_r, data_to_send,
            "Carriage return skipping suspected: data mismatch"
        );
    }

    #[test]
    fn test_pipe_helpers_and_last_bytes() {
        let (l_local, _l_remote) = UnixStream::pair().unwrap();
        let (r_local, mut r_remote) = UnixStream::pair().unwrap();

        l_local.set_nonblocking(true).unwrap();
        r_local.set_nonblocking(true).unwrap();

        let mut registry = EventRegistry::<TestProcess>::new();
        let mut pipe = Pipe::new(
            l_local,
            r_local,
            &mut registry,
            TestEvent::PipeLeft,
            TestEvent::PipeRight,
            None,
        );

        assert!(pipe.left().as_raw_fd() >= 0);
        assert!(pipe.right().as_raw_fd() >= 0);

        pipe.ignore_events(&mut registry);
        pipe.resume_events(&mut registry);
        pipe.disable_input(&mut registry);
        pipe.resume_events(&mut registry);

        assert_eq!(
            pipe.buffer_rl.get_last_n_bytes(0),
            (&[] as &[u8], &[] as &[u8])
        );

        r_remote.write_all(b"abcdef").unwrap();
        pipe.on_right_event(PollEvent::Readable, &mut registry)
            .unwrap();

        let (last_two, remainder) = pipe.buffer_rl.get_last_n_bytes(2);
        assert_eq!(last_two, b"ef");
        assert_eq!(remainder, &[]);

        let (all_bytes, remainder) = pipe.buffer_rl.get_last_n_bytes(64);
        assert_eq!(all_bytes, b"abcdef");
        assert_eq!(remainder, &[]);
    }
}
