//! Locality of the edits of chsr, checked on generated policies: a command that names a
//! part of the policy (the commands of a task, the options of a role...) changes nothing outside
//! that part of the saved file, and a command that changes nothing leaves the file as it was.
//! Otherwise an edit could silently change the rights of another role or task. The policies come
//! from a small generator with a fixed seed: the same cases run each time, and a failure names
//! its seed.

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use rootasrole_core::{
    database::migrations::FORMAT_VERSION, file::FileSettings, util::StorageMethod,
};
use serde_json::{Value, json};

use super::main;
use test_log::test;

/// The policies generated, one command each.
const CASES: u64 = 300;

/// A generator of numbers (xorshift64*), reproducible.
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
}

/// Options with a random subset of fields, and sometimes a field that this version does not
/// know, which chsr must keep.
fn options(rng: &mut Rng) -> Value {
    let candidates = [
        ("authentication", json!("skip")),
        ("bounding", json!("ignore")),
        ("root", json!("user")),
        ("umask", json!("077")),
        ("tty", json!({"owner": "target"})),
        ("password", json!({"tries": 2})),
        (
            "timeout",
            json!({"type": "tty", "duration": "00:01:00", "max_usage": 1}),
        ),
        (
            "env",
            json!({"default": "delete", "keep": ["A"], "check": ["TZ"], "set": {"S": "1"}}),
        ),
        (
            "path",
            json!({"default": "delete", "add": ["/usr/bin"], "sub": ["/tmp"]}),
        ),
        ("workdir", json!({"default": "none", "add": ["/srv"]})),
        ("future", json!(1)),
    ];
    let mut options = json!({});
    for (name, value) in candidates {
        if rng.below(3) == 0 {
            options[name] = value;
        }
    }
    options
}

/// A policy of 1 to 3 roles `r{i}` of 1 to 3 tasks `t{j}`, with actors, commands, credentials,
/// options at every level, separations of duty, parents and unknown fields.
fn generated_policy(rng: &mut Rng, path: &str) -> Value {
    let roles: Vec<Value> = (0..=rng.below(3))
        .map(|r| {
            let tasks: Vec<Value> = (0..=rng.below(3))
                .map(|t| {
                    let mut task = json!({
                        "name": format!("t{t}"),
                        "cred": {
                            "setuid": rng.pick(&["root", "nobody"]),
                            "capabilities": {"default": "none", "add": ["CAP_NET_RAW"]}
                        },
                        "commands": {"default": "none", "add": ["/usr/bin/ls", "/usr/bin/cat -n"]},
                        "options": options(rng),
                    });
                    if rng.below(4) == 0 {
                        task["future"] = json!("kept");
                    }
                    task
                })
                .collect();
            let mut role = json!({
                "name": format!("r{r}"),
                "actors": [{"type": "user", "id": 1000 + r}],
                "tasks": tasks,
                "options": options(rng),
            });
            if rng.below(3) == 0 {
                role["ssd"] = json!(["r9"]);
            }
            if rng.below(3) == 0 {
                role["parents"] = json!(["r8"]);
            }
            role
        })
        .collect();
    json!({
        // as chsr writes it
        "version": FORMAT_VERSION.to_string(),
        "storage": {"method": "json", "settings": {"path": path, "immutable": false}},
        "options": options(rng),
        "roles": roles,
    })
}

/// A command of chsr for the policy `policy`, and the part of the saved file that it may change,
/// as a JSON pointer. `{R}` and `{T}` name a role and a task of the policy.
const COMMANDS: [(&str, &str); 44] = [
    // they show and change nothing
    ("show", "/"),
    ("o show all", "/"),
    ("r {R} show all", "/"),
    ("r {R} t {T} show all", "/"),
    ("o bounding strict", "/options"),
    ("o env keep-only A,B", "/options"),
    ("o env whitelist add LC_*", "/options"),
    ("o password set --tries 5", "/options"),
    ("o timeout set --type uid", "/options"),
    ("o timeout unset --max-usage", "/options"),
    ("o tty owner caller", "/options"),
    ("o workdir blacklist add /tmp", "/options"),
    (
        "r {R} o env blacklist del LD_PRELOAD",
        "/roles/{RI}/options",
    ),
    ("r {R} o env override allow", "/roles/{RI}/options"),
    ("r {R} o path blacklist add /tmp", "/roles/{RI}/options"),
    ("r {R} o root privileged", "/roles/{RI}/options"),
    ("r {R} o timeout set --max-usage 3", "/roles/{RI}/options"),
    ("r {R} o password unset --tries", "/roles/{RI}/options"),
    ("r {R} grant -u nobody", "/roles/{RI}/actors"),
    ("r {R} revoke -u nobody", "/roles/{RI}/actors"),
    ("r {R} ssd add r7", "/roles/{RI}/ssd"),
    ("r {R} ssd purge", "/roles/{RI}/ssd"),
    ("r {R} parents set r6", "/roles/{RI}/parents"),
    ("r {R} purge actors", "/roles/{RI}/actors"),
    (
        "r {R} t {T} cmd whitelist add /usr/bin/id",
        "/roles/{RI}/tasks/{TI}/commands",
    ),
    (
        "r {R} t {T} cmd blacklist add /usr/bin/su",
        "/roles/{RI}/tasks/{TI}/commands",
    ),
    (
        "r {R} t {T} cmd setpolicy deny-all",
        "/roles/{RI}/tasks/{TI}/commands",
    ),
    (
        "r {R} t {T} cmd whitelist del /usr/bin/ls",
        "/roles/{RI}/tasks/{TI}/commands",
    ),
    (
        "r {R} t {T} cred caps whitelist add cap_sys_admin",
        "/roles/{RI}/tasks/{TI}/cred",
    ),
    (
        "r {R} t {T} cred caps setpolicy deny-all",
        "/roles/{RI}/tasks/{TI}/cred",
    ),
    (
        "r {R} t {T} cred set --setuid nobody",
        "/roles/{RI}/tasks/{TI}/cred",
    ),
    (
        "r {R} t {T} cred set --setgid-from caller",
        "/roles/{RI}/tasks/{TI}/cred",
    ),
    (
        "r {R} t {T} cred unset --setuid root",
        "/roles/{RI}/tasks/{TI}/cred",
    ),
    (
        "r {R} t {T} o auth perform",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} o env checklist add MYVAR",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} o env setpolicy keep-all",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} o path setpolicy keep-safe",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} o path whitelist purge",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    ("r {R} t {T} o umask 027", "/roles/{RI}/tasks/{TI}/options"),
    (
        "r {R} t {T} o tty owner unset",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} o workdir set /home",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} o timeout unset --type --duration --max-usage",
        "/roles/{RI}/tasks/{TI}/options",
    ),
    (
        "r {R} t {T} purpose unset",
        "/roles/{RI}/tasks/{TI}/purpose",
    ),
    (
        "r {R} task {T} purge cmd",
        "/roles/{RI}/tasks/{TI}/commands",
    ),
];

/// `value` without the part at `pointer`, so that the rest of two files can be compared.
fn without(mut value: Value, pointer: &str) -> Value {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    match value.pointer_mut(parent) {
        Some(Value::Object(object)) => {
            object.remove(key);
        }
        Some(Value::Array(array)) => {
            if let Ok(index) = key.parse::<usize>()
                && index < array.len()
            {
                array[index] = Value::Null;
            }
        }
        _ => {}
    }
    value
}

/// The policy file as chsr saves it, in the form of rootasrole-core: chsr writes a file only when
/// it changes, and writes it then in its own form (`["ls"]` for `{"default": "none", "add":
/// ["ls"]}`), so both sides of a comparison go through the same form.
fn saved(settings: &mut FileSettings, path: &PathBuf) -> Value {
    settings.save_all().unwrap();
    let text = fs::read_to_string(path).unwrap();
    let root: rootasrole_core::file::RootSettings = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("the saved file does not load: {e}\n{text}"));
    serde_json::to_value(&root).unwrap()
}

// a command of chsr changes nothing outside the part of the policy that it names, and a command
// that changes nothing leaves the file as it was
#[test]
fn test_an_edit_changes_only_its_part_of_the_policy() {
    let dir = std::env::temp_dir().join(format!("rar-chsr-locality-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    for seed in 0..CASES {
        let mut rng = Rng::new(seed);
        let path = dir.join(format!("rootasrole-{seed}.json"));
        let policy = generated_policy(&mut rng, path.to_str().unwrap());
        fs::write(&path, policy.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut settings =
            FileSettings::write_all(path.clone(), path.clone(), StorageMethod::JSON).unwrap();
        // the file as chsr writes it, before the edit
        let before = saved(&mut settings, &path);
        let roles = policy["roles"].as_array().unwrap();
        let role = rng.below(roles.len());
        let task = rng.below(roles[role]["tasks"].as_array().unwrap().len());
        let (command, part) = rng.pick(&COMMANDS);
        let fill = |text: &str| {
            text.replace("{RI}", &role.to_string())
                .replace("{TI}", &task.to_string())
                .replace("{R}", &format!("r{role}"))
                .replace("{T}", &format!("t{task}"))
        };
        let (command, part) = (fill(command), fill(part));
        let changed = main(&mut settings, command.split(' '))
            .call()
            .unwrap_or_else(|e| panic!("seed {seed}: chsr {command} failed: {e}\n{before}"));
        let after = saved(&mut settings, &path);
        if changed {
            assert_eq!(
                without(after.clone(), &part),
                without(before.clone(), &part),
                "seed {seed}: chsr {command} changed more than {part}\nbefore {before}\nafter {after}"
            );
        } else {
            assert_eq!(
                after, before,
                "seed {seed}: chsr {command} said it changed nothing"
            );
        }
        fs::remove_file(&path).unwrap();
    }
    let _ = fs::remove_dir_all(&dir);
}
