use rootasrole_exec::event::{EventHandle, EventRegistry, PollEvent, Process, StopReason};
use std::io::Write;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MyEvent {
    Read1,
    Read2,
}

struct BasicProcess {
    count: usize,
}

impl Process for BasicProcess {
    type Event = MyEvent;
    type Break = ();
    type Exit = usize;

    fn on_event(&mut self, _event: MyEvent, registry: &mut EventRegistry<Self>) {
        self.count += 1;
        registry.set_exit(self.count);
    }
}

#[test]
fn test_basic_event_loop() {
    let (mut s1, s2) = UnixStream::pair().unwrap();
    let mut registry = EventRegistry::new();
    let mut process = BasicProcess { count: 0 };

    registry.register_event(&s2, PollEvent::Readable, |_| MyEvent::Read1);

    // Make 's2' readable
    s1.write_all(b"A").unwrap();

    let reason = registry.event_loop(&mut process);
    if let StopReason::Exit(c) = reason {
        assert_eq!(c, 1);
    } else {
        panic!("Unexpected stop reason");
    }
}

struct MultiProcess {
    handle1: Option<EventHandle>,
    events: Vec<MyEvent>,
}

impl Process for MultiProcess {
    type Event = MyEvent;
    type Break = ();
    type Exit = ();

    fn on_event(&mut self, event: MyEvent, registry: &mut EventRegistry<Self>) {
        self.events.push(event);

        match event {
            MyEvent::Read2 => {
                if let Some(mut h) = self.handle1.take() {
                    h.resume(registry);
                } else {
                    registry.set_exit(());
                }
            }
            MyEvent::Read1 => (),
        }

        if self.events.len() >= 2 {
            registry.set_exit(());
        }
    }
}

#[test]
fn test_ignore_resume() {
    let (mut w1, r1) = UnixStream::pair().unwrap();
    let (mut w2, r2) = UnixStream::pair().unwrap();

    let mut registry = EventRegistry::new();
    let mut process = MultiProcess {
        handle1: None,
        events: vec![],
    };

    let mut h1 = registry.register_event(&r1, PollEvent::Readable, |_| MyEvent::Read1);
    let _h2 = registry.register_event(&r2, PollEvent::Readable, |_| MyEvent::Read2);

    h1.ignore(&mut registry);

    process.handle1 = Some(h1);

    w1.write_all(b"1").unwrap();
    w2.write_all(b"2").unwrap();

    registry.event_loop(&mut process);

    assert!(process.events.contains(&MyEvent::Read2));
    assert!(process.events.contains(&MyEvent::Read1));

    assert_eq!(process.events[0] as usize, MyEvent::Read2 as usize);
}

struct BreakProcess;
impl Process for BreakProcess {
    type Event = ();
    type Break = String;
    type Exit = ();

    fn on_event(&mut self, _event: (), registry: &mut EventRegistry<Self>) {
        registry.set_break("stopped".to_string());
    }
}

#[test]
fn test_break() {
    let (mut s1, s2) = UnixStream::pair().unwrap();
    let mut registry = EventRegistry::new();
    let mut process = BreakProcess;

    registry.register_event(&s2, PollEvent::Readable, |_| ());
    s1.write_all(b"B").unwrap();

    let reason = registry.event_loop(&mut process);
    match reason {
        StopReason::Break(s) => assert_eq!(s, "stopped"),
        StopReason::Exit(()) => panic!("Expected Break"),
    }
}
