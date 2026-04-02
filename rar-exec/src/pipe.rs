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
                if self.buffer_lr.write(&mut self.right, registry)? && !self.background {
                    self.buffer_lr.read_handle.resume(registry);
                }
                Ok(())
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
