//! Performance indicators of the finder, ignored by default. Run them in release:
//!
//! ```sh
//! cargo test --release --all-features --lib -- --ignored --nocapture finder::tests::perf
//! ```
//!
//! Each one prints how long dosr takes to decide with a policy of 1 and of 10 000 tasks, where
//! only the last task allows the command (the policies of `perf/confgen`), and the cost of one
//! task. They assert no time, which depends on the machine: compare the indicators before and
//! after a change, on the same machine.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::*;
use test_log::test;

const MANY: usize = 10_000;

/// The indicators run one at a time, so that they do not measure each other.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A role of the current user with `nb_tasks` tasks: each one allows a command that is not run,
/// the last one allows `/usr/bin/true`. `command` writes the command of a task from its number,
/// and each task runs it as `root`, or as `0` with `by_id`.
fn policy_of(nb_tasks: usize, command: impl Fn(usize) -> String, by_id: bool) -> Value {
    let (user, group) = if by_id {
        (serde_json::json!(0), serde_json::json!([0]))
    } else {
        (serde_json::json!("root"), serde_json::json!(["root"]))
    };
    let tasks = (1..=nb_tasks)
        .map(|i| {
            serde_json::json!({
                "name": format!("t{i}"),
                "cred": {
                    "setuid": {"default": "all", "fallback": user},
                    "setgid": {"default": "all", "fallback": group}
                },
                "commands": [if i == nb_tasks { "/usr/bin/true".to_string() } else { command(i) }]
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!([{
        "name": "perf",
        "actors": [{"type": "user", "id": nix::unistd::getuid().as_raw()}],
        "tasks": tasks
    }])
}

/// The mean time of a decision for `cmd` with a policy of `nb_tasks` tasks, over `iterations`
/// decisions.
fn decision_time(
    name: &str,
    method: StorageMethod,
    nb_tasks: usize,
    policy: &impl Fn(usize) -> Value,
    cmd: &str,
    iterations: u32,
) -> Duration {
    let roles = policy(nb_tasks);
    let dir = PolicyDir::new(&format!("perf-{}-{method}", name.replace(' ', "-")));
    let root = dir.0.join("rootasrole");
    write_file(&root, &root_settings(method, &root, roles), method, 0o600);
    let cli = Cli::builder().cmd_path(cmd).build();
    let cred = dummy_cred();
    let decide = || {
        let settings = find_best_exec_settings(
            &cli,
            &cred,
            &root,
            &root,
            method,
            vec![("A", "B")],
            &["/usr/bin"],
        )
        .expect("the last task allows the command");
        assert_eq!(settings.task, Some(format!("t{nb_tasks}")));
        assert!(settings.score.fully_matching());
    };
    decide();
    let start = Instant::now();
    for _ in 0..iterations {
        decide();
    }
    start.elapsed() / iterations
}

/// Prints the time of a decision for 1 and `MANY` tasks with the policy written by `policy`, and
/// the cost of one task.
fn indicator(name: &str, method: StorageMethod, cmd: &str, policy: impl Fn(usize) -> Value) {
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let one = decision_time(name, method, 1, &policy, cmd, 200);
    let many = decision_time(name, method, MANY, &policy, cmd, 10);
    let per_task = many.saturating_sub(one) / u32::try_from(MANY - 1).unwrap();
    println!(
        "perf {name} ({method}, dosr {cmd}): 1 task {one:?}, {MANY} tasks {many:?}, one task {per_task:?}"
    );
}

// a path written in full, the command given by its path, root named like in most policies
#[test]
#[ignore = "performance indicator, run in release"]
fn perf_absolute_command() {
    for method in [StorageMethod::CBOR, StorageMethod::JSON] {
        indicator("absolute command", method, "/usr/bin/true", |n| {
            policy_of(n, |i| format!("/usr/bin/true{i}"), false)
        });
    }
}

// the same with root given by its id, like the policies of perf/confgen
#[test]
#[ignore = "performance indicator, run in release"]
fn perf_target_by_id() {
    indicator("target by id", StorageMethod::CBOR, "/usr/bin/true", |n| {
        policy_of(n, |i| format!("/usr/bin/true{i}"), true)
    });
}

// the command typed by its name, searched in the PATH of each task
#[test]
#[ignore = "performance indicator, run in release"]
fn perf_command_in_path() {
    indicator("command in PATH", StorageMethod::CBOR, "true", |n| {
        policy_of(n, |i| format!("/usr/bin/true{i}"), false)
    });
}

// the commands of the policy are patterns, which are compiled
#[test]
#[ignore = "performance indicator, run in release"]
fn perf_glob_commands() {
    indicator("glob commands", StorageMethod::CBOR, "/usr/bin/true", |n| {
        policy_of(n, |i| format!("/usr/bin/true{i}*"), false)
    });
}
