//! Properties of the decision, checked on generated policies (#73): each property is a
//! hypothesis on how dosr decides, written as a test so that it never becomes a bug. The policies
//! come from a small generator with a fixed seed: the same cases run each time, without any
//! dependency, and a failure names its seed.

use std::path::PathBuf;

use serde::de::DeserializeSeed;
use serde_json::{Value, json};

use super::*;
use test_log::test;

/// The policies generated for each property.
const CASES: u64 = 200;

/// A generator of numbers (xorshift64*): enough to pick among a few choices, and reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

/// The commands that a generated task may allow: paths, arguments, patterns, and any command.
const COMMANDS: [&str; 7] = [
    "/usr/bin/ls",
    "/usr/bin/ls -l",
    "/usr/bin/ls ^.*$",
    "/usr/bin/*",
    "**",
    "/usr/bin/cat",
    "/usr/bin/l?",
];

/// The users that a generated task may run as: none written (root), root by name or by id, a
/// user that exists, and one that does not.
const USERS: [Option<&str>; 5] = [
    None,
    Some("\"root\""),
    Some("0"),
    Some("\"nobody\""),
    Some("\"rar-no-such-user\""),
];

const CAPS: [&str; 3] = ["CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"];

/// The command lines that each property asks for.
const ASKED: [(&str, &[&str]); 4] = [
    ("/usr/bin/ls", &[]),
    ("/usr/bin/ls", &["-l"]),
    ("ls", &[]),
    ("/usr/bin/cat", &[]),
];

fn task(rng: &mut Rng, name: &str) -> Value {
    let commands = match rng.below(6) {
        // every command, sometimes but one
        0 => json!({"default": "all"}),
        1 => json!({"default": "all", "del": [rng.pick(&COMMANDS)]}),
        _ => json!([rng.pick(&COMMANDS), rng.pick(&COMMANDS)]),
    };
    let caps: Vec<&str> = CAPS.iter().copied().filter(|_| rng.below(3) == 0).collect();
    let mut cred = json!({ "caps": caps });
    if let Some(user) = rng.pick(&USERS) {
        cred["setuid"] = serde_json::from_str(user).unwrap();
    }
    json!({"name": name, "cred": cred, "commands": commands})
}

/// A policy of 1 to 3 roles of 1 to 3 tasks. A role is held by the current user, by one of its
/// groups, or by another user.
fn generated_policy(rng: &mut Rng) -> Value {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();
    let roles: Vec<Value> = (0..=rng.below(3))
        .map(|r| {
            let actor = match rng.below(4) {
                0 => json!({"type": "group", "id": gid}),
                1 => json!({"type": "user", "id": uid.wrapping_add(1)}),
                _ => json!({"type": "user", "id": uid}),
            };
            let tasks: Vec<Value> = (0..=rng.below(3))
                .map(|t| task(rng, &format!("t{r}{t}")))
                .collect();
            json!({"name": format!("r{r}"), "actors": [actor], "tasks": tasks})
        })
        .collect();
    json!({ "roles": roles })
}

/// The environment of the user who runs dosr in the properties.
const USER_ENV: [(&str, &str); 5] = [
    ("A", "1"),
    ("B", "2/x"),
    ("C", "3"),
    ("LD_PRELOAD", "/tmp/x.so"),
    ("TZ", "UTC"),
];

/// What dosr decides: the role and the task chosen, with what the command runs as, or the
/// refusal.
#[derive(Debug, PartialEq)]
enum Outcome {
    Allowed {
        role: String,
        task: String,
        path: PathBuf,
        setuid: Option<u32>,
        caps: String,
    },
    Refused,
}

/// The decision of dosr for `cmd args` with `policy`, read from memory like a policy file,
/// and, with `only`, for that role and task (`dosr -r role -t task`).
fn decide(
    policy: &Value,
    cmd: &str,
    args: &[&str],
    only: Option<(&str, &str)>,
) -> SrResult<BestExecSettings> {
    let cli = Cli::builder()
        .cmd_path(cmd.to_string())
        .cmd_args(args.iter().copied())
        .maybe_opt_filter(only.map(|(role, task)| {
            FilterMatcher::builder()
                .role(role.to_string())
                .task(task.to_string())
                .build()
        }))
        .build();
    let cred = dummy_cred();
    let text = policy.to_string();
    let data = crate::finder::de::ConfigFinderDeserializer {
        cli: &cli,
        cred: &cred,
    }
    .deserialize(&mut serde_json::Deserializer::from_str(&text))
    .expect("a generated policy is valid");
    BestExecSettings::retrieve_settings(&cli, &cred, &data, USER_ENV, &["/usr/bin"])
}

fn outcome(settings: SrResult<BestExecSettings>) -> Outcome {
    match settings {
        Ok(settings) if settings.task.is_some() && settings.score.fully_matching() => {
            Outcome::Allowed {
                role: settings.role,
                task: settings.task.unwrap_or_default(),
                path: settings.final_path,
                setuid: settings.cred.setuid.map(|user| user.uid.as_raw()),
                caps: format!("{:?}", settings.cred.caps),
            }
        }
        _ => Outcome::Refused,
    }
}

/// Every role and task of `policy`, as names.
fn tasks_of(policy: &Value) -> Vec<(String, String)> {
    policy["roles"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|role| {
            role["tasks"].as_array().unwrap().iter().map(|task| {
                (
                    role["name"].as_str().unwrap().to_string(),
                    task["name"].as_str().unwrap().to_string(),
                )
            })
        })
        .collect()
}

/// `policy` with its roles, and the tasks of each role, in another order.
fn shuffled(rng: &mut Rng, policy: &Value) -> Value {
    let mut policy = policy.clone();
    let roles = policy["roles"].as_array_mut().unwrap();
    for role in roles.iter_mut() {
        rng.shuffle(role["tasks"].as_array_mut().unwrap());
    }
    rng.shuffle(roles);
    policy
}

// the decision does not depend on the order of the roles, nor of the tasks of a role: two tasks
// as good as each other are refused whatever their order (5d3dc01 was found here)
#[test]
fn test_decision_does_not_depend_on_the_order() {
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let policy = generated_policy(&mut rng);
        for (cmd, args) in ASKED {
            let expected = outcome(decide(&policy, cmd, args, None));
            for _ in 0..3 {
                let other = shuffled(&mut rng, &policy);
                assert_eq!(
                    outcome(decide(&other, cmd, args, None)),
                    expected,
                    "seed {seed}, {cmd} {args:?}\n{policy}\n{other}"
                );
            }
        }
    }
}

// the chosen task is the best one: no other task of the policy, asked for by name, matches the
// command with a better score; and a task asked for by name is chosen only if it matches
#[test]
fn test_chosen_task_is_the_best() {
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let policy = generated_policy(&mut rng);
        for (cmd, args) in ASKED {
            let Ok(best) = decide(&policy, cmd, args, None) else {
                continue;
            };
            if outcome(Ok(best.clone())) == Outcome::Refused {
                continue;
            }
            for (role, task) in tasks_of(&policy) {
                let Ok(other) = decide(&policy, cmd, args, Some((&role, &task))) else {
                    continue;
                };
                if other.task.as_deref() != Some(task.as_str()) || !other.score.fully_matching() {
                    continue;
                }
                assert!(
                    !other.score.better_fully(&best.score),
                    "seed {seed}, {cmd} {args:?}: {role}/{task} is better than {}/{:?}\n{policy}",
                    best.role,
                    best.task
                );
            }
        }
    }
}

/// `policy` with fewer rights: an actor, a task or a command less, or a command denied.
fn restricted(rng: &mut Rng, policy: &Value) -> Value {
    let mut policy = policy.clone();
    let roles = policy["roles"].as_array_mut().unwrap();
    let role = rng.below(roles.len());
    let role = &mut roles[role];
    match rng.below(3) {
        // nobody holds the role anymore
        0 => role["actors"] = json!([]),
        // a task less
        1 => {
            let tasks = role["tasks"].as_array_mut().unwrap();
            let task = rng.below(tasks.len());
            tasks.remove(task);
        }
        // a command denied in a task
        _ => {
            let tasks = role["tasks"].as_array_mut().unwrap();
            let task = rng.below(tasks.len());
            let denied = rng.pick(&COMMANDS);
            let commands = &mut tasks[task]["commands"];
            *commands = match commands.take() {
                Value::Array(allowed) => {
                    json!({"default": "none", "add": allowed, "del": [denied]})
                }
                // the commands already denied stay denied
                mut set => {
                    match set["del"].as_array_mut() {
                        Some(del) => del.push(json!(denied)),
                        None => set["del"] = json!([denied]),
                    }
                    set
                }
            };
        }
    }
    policy
}

// a restriction never allows what the policy did not: a task that the restricted policy chooses
// is one that the whole policy allows when it is asked for by name (fewer tasks can only lift a
// tie between two of them)
#[test]
fn test_restriction_never_allows_more() {
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let policy = generated_policy(&mut rng);
        for _ in 0..3 {
            let less = restricted(&mut rng, &policy);
            for (cmd, args) in ASKED {
                let Outcome::Allowed { role, task, .. } = outcome(decide(&less, cmd, args, None))
                else {
                    continue;
                };
                let whole = outcome(decide(&policy, cmd, args, Some((&role, &task))));
                assert!(
                    matches!(&whole, Outcome::Allowed { role: r, task: t, .. } if *r == role && *t == task),
                    "seed {seed}, {cmd} {args:?}: {role}/{task} allowed by\n{less}\nbut not by\n{policy}\n({whole:?})"
                );
            }
        }
    }
}

// JSON and CBOR policies give the same decision, read from their files like dosr does
#[test]
fn test_json_and_cbor_decide_the_same() {
    let dir = PolicyDir::new("properties-formats");
    for seed in 0..CASES / 4 {
        let mut rng = Rng::new(seed);
        let policy = generated_policy(&mut rng);
        for (cmd, args) in ASKED {
            let outcomes: Vec<Outcome> = [StorageMethod::JSON, StorageMethod::CBOR]
                .into_iter()
                .map(|method| {
                    let root = dir.0.join(format!("rootasrole-{method}"));
                    let settings = root_settings(method, &root, policy["roles"].clone());
                    write_file(&root, &settings, method, 0o600);
                    let cli = Cli::builder()
                        .cmd_path(cmd.to_string())
                        .cmd_args(args.iter().copied())
                        .build();
                    outcome(find_best_exec_settings(
                        &cli,
                        &dummy_cred(),
                        &root,
                        &root,
                        method,
                        vec![("A", "B")],
                        &["/usr/bin"],
                    ))
                })
                .collect();
            assert_eq!(
                outcomes[0], outcomes[1],
                "seed {seed}, {cmd} {args:?}\n{policy}"
            );
        }
    }
}

// a task whose user does not exist is never chosen, whatever the rest of the policy
#[test]
fn test_task_of_an_unknown_user_is_never_chosen() {
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let policy = generated_policy(&mut rng);
        for (cmd, args) in ASKED {
            if let Outcome::Allowed { role, task, .. } = outcome(decide(&policy, cmd, args, None)) {
                let chosen = policy["roles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["name"] == role.as_str())
                    .and_then(|r| {
                        r["tasks"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|t| t["name"] == task.as_str())
                    })
                    .unwrap();
                assert_ne!(
                    chosen["cred"]["setuid"], "rar-no-such-user",
                    "seed {seed}, {cmd} {args:?}\n{policy}"
                );
            }
        }
    }
}

/// Roles that hold one task each, allowing a command of their own, with random actors,
/// `parents` and `ssd`: `held[i]` says whether the user is an actor of the role `r{i}`.
fn hierarchy_policy(rng: &mut Rng) -> (Value, Vec<bool>) {
    let uid = nix::unistd::getuid().as_raw();
    let count = 2 + rng.below(3);
    let held: Vec<bool> = (0..count).map(|_| rng.below(2) == 0).collect();
    let others = |rng: &mut Rng, i: usize| -> Vec<String> {
        (0..count)
            .filter(|&j| j != i && rng.below(3) == 0)
            .map(|j| format!("r{j}"))
            .collect()
    };
    let roles: Vec<Value> = (0..count)
        .map(|i| {
            let actor = if held[i] { uid } else { uid.wrapping_add(1) };
            let mut role = json!({
                "name": format!("r{i}"),
                "actors": [{"type": "user", "id": actor}],
                "tasks": [{"name": format!("t{i}"), "commands": [format!("/usr/bin/rar-prop-{i}")]}],
            });
            let parents = others(rng, i);
            if !parents.is_empty() {
                role["parents"] = json!(parents);
            }
            let ssd = others(rng, i);
            if !ssd.is_empty() {
                role["ssd"] = json!(ssd);
            }
            role
        })
        .collect();
    (json!({ "roles": roles }), held)
}

/// The names that `role` lists in `field`.
fn listed<'p>(role: &'p Value, field: &str) -> Vec<&'p str> {
    role[field]
        .as_array()
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Whether dosr should allow the command of the role `r{target}`, written as the rules decided
/// on 2026-10-28: the user holds a role as its actor, or through a role it holds whose parents
/// name it; a role is excluded when the user holds a role in conflict with it, whichever of the
/// two names the other in `ssd`; the tasks of a parent come through a held role that is not
/// excluded.
fn reference_allows(policy: &Value, held: &[bool], target: usize) -> bool {
    let roles = policy["roles"].as_array().unwrap();
    let index = |name: &str| roles.iter().position(|role| role["name"] == name).unwrap();
    let holds = |i: usize| {
        held[i]
            || (0..roles.len()).any(|s| {
                held[s]
                    && listed(&roles[s], "parents").contains(&roles[i]["name"].as_str().unwrap())
            })
    };
    let in_conflict = |i: usize, j: usize| {
        let name = |k: usize| roles[k]["name"].as_str().unwrap();
        listed(&roles[i], "ssd").contains(&name(j)) || listed(&roles[j], "ssd").contains(&name(i))
    };
    let excluded = |i: usize| (0..roles.len()).any(|j| j != i && in_conflict(i, j) && holds(j));
    let name = roles[target]["name"].as_str().unwrap();
    !excluded(target)
        && (held[target]
            || roles.iter().any(|senior| {
                let s = index(senior["name"].as_str().unwrap());
                held[s] && !excluded(s) && listed(senior, "parents").contains(&name)
            }))
}

// the separation of duties holds through the hierarchy: dosr allows the command of a role
// exactly when the reference rules do, for random actors, parents and conflicts
#[cfg(all(feature = "hierarchy", feature = "ssd"))]
#[test]
fn test_separation_of_duties_through_the_hierarchy() {
    crate::finder::api::register_plugins();
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let (policy, held) = hierarchy_policy(&mut rng);
        for target in 0..held.len() {
            let cmd = format!("/usr/bin/rar-prop-{target}");
            let allowed = matches!(
                outcome(decide(&policy, &cmd, &[], None)),
                Outcome::Allowed { ref role, .. } if *role == format!("r{target}")
            );
            assert_eq!(
                allowed,
                reference_allows(&policy, &held, target),
                "seed {seed}, r{target}, held {held:?}\n{policy}"
            );
        }
    }
}

/// The fields of the options that hold one value each, with the values that a level may give
/// them: `(option, field)`, `field` empty for an option that is the value itself.
const SCALARS: [(&str, &str, [&str; 2]); 11] = [
    ("authentication", "", ["\"perform\"", "\"skip\""]),
    ("bounding", "", ["\"strict\"", "\"ignore\""]),
    ("root", "", ["\"user\"", "\"privileged\""]),
    ("umask", "", ["\"022\"", "\"077\""]),
    ("tty", "owner", ["\"caller\"", "\"target\""]),
    ("password", "tries", ["1", "5"]),
    ("password", "delay", ["\"00:00:01\"", "\"00:00:03\""]),
    ("timeout", "type", ["\"tty\"", "\"uid\""]),
    ("timeout", "duration", ["\"00:01:00\"", "\"00:05:00\""]),
    ("timeout", "max_usage", ["1", "3"]),
    ("timeout", "type", ["\"ppid\"", "\"tty\""]),
];

/// Options that set a random subset of the scalar fields, each with one of its values.
fn scalar_options(rng: &mut Rng) -> Value {
    let mut options = json!({});
    for (option, field, values) in SCALARS {
        if rng.below(3) != 0 {
            continue;
        }
        let text: &&str = rng.pick(&values);
        let value: Value = serde_json::from_str(text).unwrap();
        if field.is_empty() {
            options[option] = value;
        } else {
            if options.get(option).is_none() {
                options[option] = json!({});
            }
            options[option][field] = value;
        }
    }
    options
}

/// `value` as JSON, to compare it with the JSON of the policy.
fn to_json(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).unwrap()
}

/// The value of `option.field` at the most specific of `levels` (task, role, then policy) that
/// sets it, as JSON; `None` when none sets it, for the build-time default.
fn nearest<'v>(levels: &[&'v Value], option: &str, field: &str) -> Option<&'v Value> {
    levels.iter().find_map(|level| {
        let value = level.get(option)?;
        if field.is_empty() {
            Some(value)
        } else {
            value.get(field)
        }
    })
}

// a field that a level does not set is inherited from the levels above it, one field at a time:
// the value of each scalar field is the one of the most specific level that sets it, else the
// build-time default, so that a protection never disappears because a lower level does not
// mention it (the timeout lost its max_usage and scope when a task changed its duration)
#[test]
fn test_absent_field_is_inherited() {
    let uid = nix::unistd::getuid().as_raw();
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let (policy_opt, role_opt, task_opt) = (
            scalar_options(&mut rng),
            scalar_options(&mut rng),
            scalar_options(&mut rng),
        );
        let policy = json!({
            "options": policy_opt,
            "roles": [{
                "name": "r",
                "actors": [{"type": "user", "id": uid}],
                "options": role_opt,
                "tasks": [{"name": "t", "commands": ["/usr/bin/ls"], "options": task_opt}]
            }]
        });
        let settings = decide(&policy, "/usr/bin/ls", &[], None)
            .unwrap_or_else(|e| panic!("seed {seed}: {e:?}\n{policy}"));
        let levels = [&task_opt, &role_opt, &policy_opt];
        let check = |option: &str, field: &str, actual: Value, default: Value| {
            let expected = nearest(&levels, option, field).cloned().unwrap_or(default);
            assert_eq!(actual, expected, "seed {seed}, {option}.{field}\n{policy}");
        };
        check(
            "authentication",
            "",
            to_json(&settings.auth),
            to_json(&rootasrole_core::util::AUTHENTICATION),
        );
        check(
            "bounding",
            "",
            to_json(&settings.bounding),
            to_json(&rootasrole_core::util::BOUNDING),
        );
        check(
            "root",
            "",
            to_json(&settings.root),
            to_json(&rootasrole_core::util::PRIVILEGED),
        );
        check(
            "umask",
            "",
            to_json(&settings.umask),
            to_json(&rootasrole_core::util::UMASK),
        );
        check(
            "tty",
            "owner",
            to_json(&settings.tty_owner),
            to_json(&rootasrole_core::util::TTY_OWNER),
        );
        let timeout = serde_json::to_value(&settings.timeout).unwrap();
        for field in ["type", "duration", "max_usage"] {
            let default = serde_json::to_value(
                super::super::options::BorrowedOptStack::new(None).calc_timeout(),
            )
            .unwrap()
            .get(field)
            .cloned()
            .unwrap_or(Value::Null);
            check(
                "timeout",
                field,
                timeout.get(field).cloned().unwrap_or(Value::Null),
                default,
            );
        }
        let password = &settings.password;
        check(
            "password",
            "tries",
            to_json(&password.tries.get()),
            to_json(&rootasrole_core::util::PASSWORD_TRIES.get()),
        );
        check(
            "password",
            "delay",
            serde_json::to_value(
                rootasrole_core::database::options::SPassword::builder()
                    .delay(password.delay)
                    .build(),
            )
            .unwrap()["delay"]
                .clone(),
            serde_json::to_value(
                rootasrole_core::database::options::SPassword::builder()
                    .delay(rootasrole_core::util::PASSWORD_DELAY)
                    .build(),
            )
            .unwrap()["delay"]
                .clone(),
        );
    }
}

/// A random subset of `names`, possibly empty.
fn subset(rng: &mut Rng, names: &[&str]) -> Value {
    json!(
        names
            .iter()
            .filter(|_| rng.below(2) == 0)
            .collect::<Vec<_>>()
    )
}

/// Random env and path options, written as an administrator or chsr would.
fn list_options(rng: &mut Rng, options: &mut Value) {
    if rng.below(2) == 0 {
        let mut env = json!({});
        if rng.below(2) == 0 {
            env["default"] = json!(rng.pick(&["delete", "keep", "inherit"]));
        }
        for list in ["keep", "check", "delete"] {
            if rng.below(3) == 0 {
                env[list] = subset(rng, &["A", "B", "C", "LD_*", "TZ"]);
            }
        }
        if rng.below(4) == 0 {
            env["set"] = json!({"S": "set"});
        }
        options["env"] = env;
    }
    if rng.below(2) == 0 {
        let mut path = json!({});
        if rng.below(2) == 0 {
            path["default"] = json!(rng.pick(&["delete", "keep-safe", "keep-unsafe", "inherit"]));
        }
        for list in ["add", "sub"] {
            if rng.below(3) == 0 {
                path[list] = subset(rng, &["/usr/bin", "/usr/local/bin", "/bin"]);
            }
        }
        options["path"] = path;
    }
}

/// A generated policy with options at every level, and sometimes the parents and conflicts of
/// its roles.
fn full_policy(rng: &mut Rng) -> Value {
    let mut policy = generated_policy(rng);
    policy["options"] = scalar_options(rng);
    list_options(rng, &mut policy["options"]);
    let names: Vec<String> = policy["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|role| role["name"].as_str().unwrap().to_string())
        .collect();
    for role in policy["roles"].as_array_mut().unwrap() {
        role["options"] = scalar_options(rng);
        list_options(rng, &mut role["options"]);
        for task in role["tasks"].as_array_mut().unwrap() {
            task["options"] = scalar_options(rng);
            list_options(rng, &mut task["options"]);
            if rng.below(4) == 0 {
                task["cred"]["setgid"] = json!(rng.pick(&["root", "rar-no-such-group"]));
            }
        }
        for field in ["parents", "ssd"] {
            if rng.below(4) == 0 {
                role[field] = json!([rng.pick(&names)]);
            }
        }
    }
    policy
}

/// What a decision gives the command, to compare two decisions: the task, its credentials, its
/// options and its environment.
fn summary(settings: &SrResult<BestExecSettings>) -> String {
    match settings {
        Ok(s) => {
            let mut env: Vec<_> = s.env.iter().collect();
            env.sort();
            let groups = s
                .cred
                .setgroups
                .as_ref()
                .map(|groups| groups.iter().map(|g| g.gid.as_raw()).collect::<Vec<_>>());
            format!(
                "{} {:?} {:?} {:?} {groups:?} {:?} {:?} {:?} {:?} {:?} {env:?}",
                s.role,
                s.task,
                s.final_path,
                s.cred.caps,
                s.auth,
                s.bounding,
                s.root,
                s.timeout,
                s.env_path
            )
        }
        Err(e) => format!("{e:?}"),
    }
}

// chsr reads the policy with rootasrole-core and writes it back: a policy read and written by
// core decides as the policy itself, so that saving an unrelated change never changes what
// dosr allows
#[test]
fn test_core_round_trip_keeps_the_decision() {
    crate::finder::api::register_plugins();
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let policy = full_policy(&mut rng);
        let core: rootasrole_core::database::structs::SPolicy =
            serde_json::from_value(policy.clone())
                .unwrap_or_else(|e| panic!("seed {seed}: core refuses the policy: {e}\n{policy}"));
        let written = serde_json::to_value(&core).unwrap();
        for (cmd, args) in ASKED {
            let before = decide(&policy, cmd, args, None);
            let after = decide(&written, cmd, args, None);
            assert_eq!(
                summary(&after),
                summary(&before),
                "seed {seed}, {cmd} {args:?}\npolicy {policy}\nwritten by core {written}"
            );
        }
    }
}

/// The variables of `vars`, and the variables `extra` that the policy may set, that the command
/// of the only task of `policy` receives, decided for a user whose environment is `vars`.
fn received(policy: &Value, vars: &[(&str, &str)], extra: &[&str]) -> Vec<String> {
    let cli = Cli::builder().cmd_path("/usr/bin/ls").build();
    let cred = dummy_cred();
    let text = policy.to_string();
    let data = crate::finder::de::ConfigFinderDeserializer {
        cli: &cli,
        cred: &cred,
    }
    .deserialize(&mut serde_json::Deserializer::from_str(&text))
    .expect("a valid policy");
    let settings = BestExecSettings::retrieve_settings(
        &cli,
        &cred,
        &data,
        vars.iter().copied(),
        &["/usr/bin"],
    )
    .expect("the task allows the command");
    let mut names: Vec<String> = vars
        .iter()
        .map(|(name, _)| *name)
        .chain(extra.iter().copied())
        .filter(|name| settings.env.contains_key(*name))
        .map(ToString::to_string)
        .collect();
    names.sort();
    names
}

/// A policy whose global options are `global`, with one task whose options are `task`.
fn env_policy(global: &Value, task: &Value) -> Value {
    json!({
        "options": global,
        "roles": [{
            "name": "r",
            "actors": [{"type": "user", "id": nix::unistd::getuid().as_raw()}],
            "tasks": [{"name": "t", "commands": ["/usr/bin/ls"], "options": task}]
        }]
    })
}

// the examples of "Concrete behavior example" in the env section of the book
// (book/src/configuration.md), with the environment of the user that it gives
#[test]
fn test_env_examples_of_the_book() {
    let user = [
        ("EDITOR", "vim"),
        ("PAGER", "less"),
        ("FOO", "bar"),
        ("LD_PRELOAD", "/tmp/x.so"),
        ("LANG", "fr_FR.UTF-8"),
        ("LC_ALL", "../x"),
        ("TZ", "Europe/Paris"),
        ("BASH_FUNC_f%%", "() { id; }"),
    ];
    let global = json!({"env": {"default": "delete", "keep": ["EDITOR"]}});
    for (task, expected) in [
        (json!({}), vec!["EDITOR", "LANG", "TZ"]),
        (
            json!({"env": {"keep": ["PAGER"]}}),
            vec!["EDITOR", "LANG", "PAGER", "TZ"],
        ),
        (
            json!({"env": {"default": "delete", "keep": ["PAGER"]}}),
            vec!["LANG", "PAGER", "TZ"],
        ),
        (
            json!({"env": {"default": "delete", "keep": [], "check": []}}),
            vec![],
        ),
        (
            json!({"env": {"default": "keep"}}),
            vec!["EDITOR", "FOO", "LANG", "PAGER", "TZ"],
        ),
    ] {
        assert_eq!(
            received(&env_policy(&global, &task), &user, &[]),
            expected,
            "task {task}"
        );
    }
}

/// Whether the env pattern `pattern` (`*` for any characters) matches `name`.
fn env_pattern_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.starts_with(head)
                && (0..=name.len() - head.len())
                    .any(|start| env_pattern_matches(tail, &name[head.len() + start..]))
        }
    }
}

/// The variables that the command receives, decided by the rules of the env section of the
/// book: the levels apply in order (the build-time defaults, then global, role and task
/// options); a level that declares `default` (`delete` or `keep`) sets the mode and replaces
/// the lists that it defines, a level that does not declare it adds its lists to the inherited
/// ones; then a shell function never passes, `delete` mode passes `keep` and checked `check`
/// variables, `keep` mode passes what `delete` does not name, checked when `check` names it, and
/// `set` comes last.
fn reference_env(levels: &[&Value], user: &[(&str, &str)]) -> Vec<String> {
    use rootasrole_core::util::{
        ENV_CHECK_LIST_SLICE, ENV_DEFAULT_BEHAVIOR, ENV_DELETE_LIST_SLICE, ENV_KEEP_LIST_SLICE,
        ENV_SET_LIST_SLICE,
    };
    let owned = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut keep_mode = to_json(&ENV_DEFAULT_BEHAVIOR) == json!("keep");
    let mut lists = [
        owned(ENV_KEEP_LIST_SLICE),
        owned(ENV_CHECK_LIST_SLICE),
        owned(ENV_DELETE_LIST_SLICE),
        ENV_SET_LIST_SLICE
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect(),
    ];
    for level in levels {
        let Some(env) = level.get("env") else {
            continue;
        };
        let declared = match env.get("default").and_then(Value::as_str) {
            Some("keep") => {
                keep_mode = true;
                true
            }
            Some("delete") => {
                keep_mode = false;
                true
            }
            _ => false,
        };
        for (list, field) in lists.iter_mut().zip(["keep", "check", "delete", "set"]) {
            let Some(entries) = env.get(field) else {
                continue;
            };
            let entries: Vec<String> = match entries {
                Value::Object(set) => set.keys().cloned().collect(),
                _ => entries
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| entry.as_str().unwrap().to_string())
                    .collect(),
            };
            if declared {
                *list = entries;
            } else {
                list.extend(entries);
            }
        }
    }
    let [keep, check, delete, set] = lists;
    let named = |list: &[String], name: &str| list.iter().any(|p| env_pattern_matches(p, name));
    let safe = |value: &str| !value.contains(['/', '%']);
    let mut received: Vec<String> = user
        .iter()
        .filter(|(_, value)| !value.starts_with("()"))
        .filter(|(name, value)| {
            let checked = !named(&check, name) || safe(value);
            if keep_mode {
                !named(&delete, name) && checked
            } else {
                (named(&keep, name) && checked) || (named(&check, name) && safe(value))
            }
        })
        .map(|(name, _)| (*name).to_string())
        .chain(set)
        .collect();
    received.sort();
    received.dedup();
    received
}

// the env options decide the environment of the command as the book says, for random options
// at the global, role and task levels
#[test]
fn test_env_follows_the_book() {
    let user = [
        ("A", "1"),
        ("B", "2/x"),
        ("C", "3"),
        ("LD_PRELOAD", "/tmp/x.so"),
        ("TZ", "UTC"),
        ("F", "() { id; }"),
    ];
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let mut levels = [json!({}), json!({}), json!({})];
        for level in &mut levels {
            list_options(&mut rng, level);
            if let Some(path) = level.as_object_mut() {
                path.remove("path");
            }
        }
        let [global, role, task] = &levels;
        let policy = json!({
            "options": global,
            "roles": [{
                "name": "r",
                "actors": [{"type": "user", "id": nix::unistd::getuid().as_raw()}],
                "options": role,
                "tasks": [{"name": "t", "commands": ["/usr/bin/ls"], "options": task}]
            }]
        });
        let mut expected = reference_env(&[global, role, task], &user);
        let actual = received(&policy, &user, &["S"]);
        expected.retain(|name| name == "S" || user.iter().any(|(var, _)| var == name));
        assert_eq!(actual, expected, "seed {seed}\n{policy}");
    }
}
