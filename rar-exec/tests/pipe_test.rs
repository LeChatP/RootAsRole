use rootasrole_exec::event::{EventRegistry, PollEvent, Process};
use rootasrole_exec::pipe::{IoLogger, Pipe};
use std::io::{Read, Write};
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
