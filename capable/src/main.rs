use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fs::{canonicalize, metadata};
use std::os::unix::prelude::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::exit;

use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, thread, vec};
use std::panic::set_hook;
use aya::maps::{Array, HashMap, Map, MapData};
use aya::programs::{KProbe, Program};
use aya::util::KernelVersion;
use aya::{include_bytes_aligned, Ebpf, Pod};
use aya_log::EbpfLogger;
use capable_common::{NsId, Request};
use capctl::{ambient, Cap, CapSet, CapState, ParseCapError};
use log::{debug, warn};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use tabled::settings::object::Columns;

use tabled::settings::{Modify, Style, Width};
use tabled::{Table, Tabled};
use tokio::runtime::Runtime;
use tokio::signal;
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt;

type Key = i32;

mod version;

struct Cli {
    /// Specify a delay before killing the process
    sleep: Option<u64>,
    /// collecting data on system and print result at the end
    daemon: bool,

    /// Pass all capabilities when executing the command,
    capabilities: CapSet,

    /// Print output in JSON format, ignore stdin/out/err
    json: bool,

    /// Specify a command to execute with arguments
    command: Vec<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            sleep: None,
            daemon: false,
            capabilities: CapSet::empty(),
            json: false,
            command: Vec::new(),
        }
    }
}

#[derive(Tabled, Serialize, Deserialize)]
#[tabled(rename_all = "UPPERCASE")]
struct CapabilitiesTable {
    pid: u32,
    ppid: u32,
    uid: String,
    gid: String,
    ns: u32,
    parent_ns: u32,
    name: String,
    capabilities: String,
}

const MAX_CHECK: u64 = 10;

pub fn capset_to_vec(set: &CapSet) -> Vec<String> {
    set.iter().map(|c| format!("CAP_{:?}", c)).collect()
}

pub fn capset_to_string(set: &CapSet) -> String {
    if set == &!CapSet::empty() {
        return String::from("ALL");
    }
    set.iter()
        .fold(String::new(), |mut acc, cap| {
            acc.push_str(&format!("CAP_{:?} ", cap));
            acc
        })
        .trim_end()
        .to_string()
}

fn get_cap(val: u8) -> Option<Cap> {
    match val {
        0 => Some(Cap::CHOWN),
        1 => Some(Cap::DAC_OVERRIDE),
        2 => Some(Cap::DAC_READ_SEARCH),
        3 => Some(Cap::FOWNER),
        4 => Some(Cap::FSETID),
        5 => Some(Cap::KILL),
        6 => Some(Cap::SETGID),
        7 => Some(Cap::SETUID),
        8 => Some(Cap::SETPCAP),
        9 => Some(Cap::LINUX_IMMUTABLE),
        10 => Some(Cap::NET_BIND_SERVICE),
        11 => Some(Cap::NET_BROADCAST),
        12 => Some(Cap::NET_ADMIN),
        13 => Some(Cap::NET_RAW),
        14 => Some(Cap::IPC_LOCK),
        15 => Some(Cap::IPC_OWNER),
        16 => Some(Cap::SYS_MODULE),
        17 => Some(Cap::SYS_RAWIO),
        18 => Some(Cap::SYS_CHROOT),
        19 => Some(Cap::SYS_PTRACE),
        20 => Some(Cap::SYS_PACCT),
        21 => Some(Cap::SYS_ADMIN),
        22 => Some(Cap::SYS_BOOT),
        23 => Some(Cap::SYS_NICE),
        24 => Some(Cap::SYS_RESOURCE),
        25 => Some(Cap::SYS_TIME),
        26 => Some(Cap::SYS_TTY_CONFIG),
        27 => Some(Cap::MKNOD),
        28 => Some(Cap::LEASE),
        29 => Some(Cap::AUDIT_WRITE),
        30 => Some(Cap::AUDIT_CONTROL),
        31 => Some(Cap::SETFCAP),
        32 => Some(Cap::MAC_OVERRIDE),
        33 => Some(Cap::MAC_ADMIN),
        34 => Some(Cap::SYSLOG),
        35 => Some(Cap::WAKE_ALARM),
        36 => Some(Cap::BLOCK_SUSPEND),
        37 => Some(Cap::AUDIT_READ),
        38 => Some(Cap::PERFMON),
        39 => Some(Cap::BPF),
        40 => Some(Cap::CHECKPOINT_RESTORE),
        _ => None,
    }
}

fn caps_from_u64(caps: u64) -> CapSet {
    let mut capset = CapSet::empty();
    for i in 0..64 {
        if caps & (1 << i) != 0 {
            capset.add(get_cap(i).unwrap());
        }
    }
    capset
}

fn union_all_childs(
    nsinode: u32,
    graph: &std::collections::HashMap<u32, Vec<(u32, CapSet)>>,
) -> CapSet {
    let mut result = CapSet::empty();
    for ns in graph.get(&nsinode).unwrap_or(&Vec::new()) {
        result = result.union(ns.1);
        if graph.contains_key(&ns.0) && ns.0 != nsinode {
            result = result.union(union_all_childs(ns.0, graph));
        }
    }
    result
}

fn print_program_capabilities<T>(
    nsinode: &u32,
    capabilities_map: &HashMap<T, Key, u64>,
    pnsid_nsid_map: &HashMap<T, Key, u64>,
    json: bool,
) -> Result<(), Box<dyn Error>>
where
    T: Borrow<MapData>,
{
    let mut graph = std::collections::HashMap::new();
    let mut init = CapSet::empty();
    setbpf_effective(true);
    for key in capabilities_map.keys() {
        let pid = key.inspect_err(|err| {
            eprintln!("Failed to get pid : {:?}", err.to_string());
            exit(-1);
        })?;
        let pinum_inum = pnsid_nsid_map.get(&pid, 0).unwrap_or(0);
        let child = pinum_inum as u32;
        let parent = (pinum_inum >> 32) as u32;
        graph.entry(parent).or_insert_with(Vec::new).push((
            child,
            caps_from_u64(capabilities_map.get(&pid, 0).unwrap_or(0)),
        ));
        if child == *nsinode {
            init = caps_from_u64(capabilities_map.get(&pid, 0).unwrap_or(0));
        }
    }
    setbpf_effective(false);
    let result = init.union(union_all_childs(*nsinode, &graph));
    if json {
        println!("{}", serde_json::to_string(&capset_to_vec(&result))?);
    } else {
        println!("Here's all capabilities intercepted for this program :\n{}\nWARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\nWARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant",
        capset_to_string(&result));
    }
    Ok(())
}

fn find_from_envpath<P>(exe_name: &P) -> Option<PathBuf>
where
    P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(exe_name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}

fn get_exec_and_args(command: &mut Vec<String>) -> (PathBuf, Vec<String>) {
    let mut exec_path = command[0].parse().unwrap();
    let exec_args;
    if let Some(program) = find_from_envpath(&command[0]) {
        exec_path = program;
        exec_args = command[1..].to_vec();
    } else {
        // encapsulate the command in sh command
        command[0] = canonicalize(exec_path.clone())
            .unwrap_or(exec_path)
            .to_str()
            .unwrap()
            .to_string();
        exec_path = PathBuf::from("/bin/sh");
        exec_args = vec!["-c".to_string(), shell_words::join(command)];
    }
    (exec_path, exec_args)
}

fn print_all<T>(
    capabilities_map: &HashMap<T, Key, u64>,
    pnsid_nsid_map: &HashMap<T, Key, u64>,
    uid_gid_map: &HashMap<T, Key, u64>,
    ppid_map: &HashMap<T, Key, i32>,
    json: bool,
) -> Result<(), anyhow::Error>
where
    T: Borrow<MapData>,
{
    let mut capabilities_table = Vec::new();
    for key in capabilities_map.keys() {
        let pid = key?;
        let uid_gid = uid_gid_map.get(&pid, 0).unwrap_or(0);
        let ppid = ppid_map.get(&pid, 0).unwrap_or(0);
        let pinum_inum = pnsid_nsid_map.get(&pid, 0).unwrap_or(0);
        let ns = (pinum_inum & 0xffffffff) as u32;
        let parent_ns = (pinum_inum >> 32) as u32;
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
            .unwrap_or(std::path::PathBuf::from(""));
        let name: &str = exe.to_str().unwrap_or("");
        let capabilities = capabilities_map.get(&pid, 0).unwrap_or(0);
        let capabilities = caps_from_u64(capabilities);
        let uid = (uid_gid & 0xffffffff) as u32;
        //find username from uid
        let username = nix::unistd::User::from_uid(Uid::from_raw(uid))
            .map_or(uid.to_string(), |u| u.map_or(uid.to_string(), |u| u.name));
        let gid = (uid_gid >> 32) as u32;
        let groupname = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))
            .map_or(gid.to_string(), |g| g.map_or(gid.to_string(), |g| g.name));
        capabilities_table.push(CapabilitiesTable {
            pid: pid as u32,
            ppid: ppid as u32,
            uid: username,
            gid: groupname,
            ns,
            parent_ns,
            name: String::from(name),
            capabilities: capset_to_string(&capabilities),
        });
    }
    if json {
        println!("{}", serde_json::to_string(&capabilities_table)?);
    } else {
        println!(
            "\n{}",
            Table::new(&capabilities_table)
                .with(Style::modern())
                .with(Modify::new(Columns::single(3)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::single(2)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::single(6)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::last()).with(Width::wrap(52).keep_words()))
        );
    }

    Ok(())
}

fn remove_outer_quotes(input: &str) -> String {
    if input.len() >= 2 && input.starts_with('"') && input.ends_with('"') {
        remove_outer_quotes(&input[1..input.len() - 1])
    } else if input.len() >= 2 && input.starts_with('\'') && input.ends_with('\'') {
        remove_outer_quotes(&input[1..input.len() - 1])
    } else {
        input.to_string()
    }
}

pub fn escape_parser_string<S>(s: S) -> String
where
    S: AsRef<str>,
{
    remove_outer_quotes(s.as_ref()).replace("\"", "\\\"")
}

pub fn parse_capset_iter<'a, I>(iter: I) -> Result<CapSet, ParseCapError>
where
    I: Iterator<Item = &'a str>,
{
    let mut res = CapSet::empty();

    for part in iter {
        match part.parse() {
            Ok(cap) => res.add(cap),
            Err(error) => {
                return Err(error);
            }
        }
    }
    Ok(res)
}

const CAPABILITIES_ERROR: &str =
    "You need at least setpcap, sys_admin, bpf, sys_resource, sys_ptrace capabilities to run capable";
fn cap_effective_error(caplist: &str) -> String {
    format!(
        "Unable to toggle {} privilege. {}",
        caplist, CAPABILITIES_ERROR
    )
}

fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

fn setpcap_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETPCAP, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SETPCAP"));
    })
}

fn setbpf_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::BPF, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("BPF"));
    })
}

fn setadmin_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SYS_ADMIN, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SYS_ADMIN"));
    })
}

fn setresource_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SYS_RESOURCE, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SYS_RESOURCE"));
    })
}

fn setptrace_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SYS_PTRACE, enable).inspect_err(|_| {
        eprintln!("{}", cap_effective_error("SYS_PTRACE"));
    })
}

fn getopt<S, I>(s: I) -> Result<Cli, anyhow::Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = Cli::default();
    let mut iter = s.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_ref() {
            "-s" | "--sleep" => {
                args.sleep = iter.next().and_then(|s| s.as_ref().parse::<u64>().ok());
            }
            "-d" | "--daemon" => {
                args.daemon = true;
            }
            "-c" | "--capabilities" => {
                args.capabilities = iter
                    .next()
                    .and_then(|s| {
                        Some(
                            parse_capset_iter(s.as_ref().split(','))
                                .ok()
                                .unwrap_or(CapSet::empty()),
                        )
                    })
                    .unwrap_or(CapSet::empty());
            }
            "-j" | "--json" => {
                args.json = true;
            }
            _ => {
                if arg.as_ref().starts_with('-') {
                    return Err(anyhow::anyhow!("Unknown option: {}", arg.as_ref()));
                } else {
                    args.command.push(escape_parser_string(arg));
                    break;
                }
            }
        }
    }
    while let Some(arg) = iter.next() {
        args.command.push(escape_parser_string(arg));
    }
    Ok(args)
}

fn run_command(
    cli_args: &mut Cli,
    nsclone: Rc<RefCell<u32>>,
    config_map: Rc<RefCell<Array<MapData, u32>>>,
) -> Result<i32, anyhow::Error> {
    let (path, args) = get_exec_and_args(&mut cli_args.command);
    let namespaces = vec![&unshare::Namespace::Pid];
    let capabilities = cli_args.capabilities.clone();
    let mut cmd = unshare::Command::new(path);

    unsafe {
        cmd.pre_exec(move || {
            let mut capstate = CapState::empty();
            nix::sys::prctl::set_keepcaps(false).expect("Failed to set keepcaps");
            setpcap_effective(true).expect("Failed to setpcap effective");
            ambient::clear().expect("Failed to clear ambiant caps");
            capstate.inheritable = capabilities;
            capstate.permitted = capabilities;
            capstate.effective = capabilities;
            capstate.set_current().expect("Failed to set current cap");
            Ok(())
        })
    };
    setadmin_effective(true)?;

    //avoid output
    let child: Arc<Mutex<unshare::Child>> = Arc::new(Mutex::new(
        cmd.args(&args)
            .before_unfreeze(move |id| {
                setptrace_effective(true)?;
                let fnspid =
                    metadata(format!("/proc/{}/ns/pid", id)).expect("failed to open pid ns");
                setptrace_effective(false)?;
                nsclone.as_ref().replace(fnspid.ino() as u32);
                config_map
                    .as_ref()
                    .borrow_mut()
                    .set(0, fnspid.ino() as u32, 0)?;
                Ok(())
            })
            .unshare(namespaces)
            .stdout(if cli_args.json {
                unshare::Stdio::null()
            } else {
                unshare::Stdio::inherit()
            })
            .stderr(if cli_args.json {
                unshare::Stdio::null()
            } else {
                unshare::Stdio::inherit()
            })
            .stdin(if cli_args.json {
                unshare::Stdio::null()
            } else {
                unshare::Stdio::inherit()
            })
            .spawn()
            .expect("failed to spawn child"),
    ));
    setadmin_effective(false)?;
    let cloned = child.clone();
    let pid = child.try_lock().unwrap().id() as i32;

    thread::spawn(move || {
        let rt = Runtime::new().unwrap();
        rt.block_on(signal::ctrl_c())
            .expect("failed to wait for ctrl-c");
        let nixpid = nix::unistd::Pid::from_raw(pid);
        nix::sys::signal::kill(nixpid, nix::sys::signal::Signal::SIGINT)
            .expect("failed to send SIGINT");
        let mut i = 0;
        if nix::sys::wait::waitpid(nixpid, Some(WaitPidFlag::WNOHANG)).expect("Fail to wait pid")
            == WaitStatus::StillAlive
            && i < MAX_CHECK
        {
            i += 1;
            thread::sleep(Duration::from_millis(100));
        }
        if i >= MAX_CHECK {
            eprintln!("SIGINT wait is timed-out\n");
            child
                .try_lock()
                .unwrap()
                .kill()
                .expect("failed to send SIGKILL");
            i = 0;
            while nix::sys::wait::waitpid(nixpid, Some(WaitPidFlag::WNOHANG))
                .expect("Fail to wait pid")
                == WaitStatus::StillAlive
                && i < MAX_CHECK
            {
                thread::sleep(Duration::from_millis(100));
                i += 1;
            }
            if i >= MAX_CHECK {
                exit(-1);
            }
        }
        Ok::<(), ()>(())
    });

    let exit_status = cloned
        .try_lock()
        .unwrap()
        .wait()
        .expect("failed to wait on child");
    debug!("child exited with {:?}", exit_status);
    //print_all(&capabilities_map, &pnsid_nsid_map, &uid_gid_map, &ppid_map)?;

    if exit_status.success() {
        Ok(0)
    } else {
        Ok(exit_status.code().unwrap_or(-1))
    }
}

fn load_and_attach_program(
    bpf: &mut Ebpf,
    call: &str,
    fn_name: &str,
    offset: u64,
) -> Result<(), anyhow::Error> {
    debug!("loading and attaching program {}", call);
    setbpf_effective(true)?;
    setadmin_effective(true)?;
    let program: &mut KProbe = bpf.program_mut(call).unwrap().try_into()?;
    program.load()?;
    program.attach(fn_name, offset)?;
    setbpf_effective(false)?;
    setadmin_effective(false)?;
    debug!("program {} loaded and attached", call);
    Ok(())
}

#[cfg(debug_assertions)]
pub fn subsribe(tool: &str) {
    use std::io;
    let identity = CString::new(tool).unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let _syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_writer(io::stdout)
        .finish()
        .init();
}

#[cfg(not(debug_assertions))]
pub fn subsribe(tool: &str) {
    use std::panic::set_hook;

    let identity = CString::new(tool).unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .compact()
        .with_max_level(Level::WARN)
        .with_file(false)
        .with_timer(false)
        .with_line_number(false)
        .with_target(false)
        .without_time()
        .with_writer(syslog)
        .finish()
        .init();
    set_hook(Box::new(|info| {
        if let Some(s) = info.payload().downcast_ref::<String>() {
            println!("{}", s);
        }
    }));
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    subsribe("capable");
    ambient::clear().expect("Failed to clear ambiant caps");
    debug!("capable started");

    if KernelVersion::current()?.code() != version::LINUX_VERSION_CODE {
        let major = version::LINUX_VERSION_CODE >> 16;
        let minor = (version::LINUX_VERSION_CODE >> 8) & 0xff;
        let patch = version::LINUX_VERSION_CODE & 0xff;
        let current = KernelVersion::current()?.code();
        let current_major = current >> 16;
        let current_minor = (current >> 8) & 0xff;
        let current_patch = current & 0xff;
        warn!("This program was compiled for kernel version {}.{}.{}, but the current kernel version is {}.{}.{}",
              major, minor, patch, current_major, current_minor, current_patch);
        warn!("This may cause the program to fail or behave unexpectedly");
    }

    debug!("setting capabilities");

    let mut capstate = CapState::get_current().expect("Failed to get current cap");
    capstate.inheritable = CapSet::empty();
    capstate.effective = CapSet::empty();
    capstate.set_current().expect("Failed to set current cap");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    setresource_effective(true)?;
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    setresource_effective(false)?;
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    setbpf_effective(true)?;
    setadmin_effective(true)?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/capable"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/capable"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF {}", e);
    }
    load_and_attach_program(&mut bpf, "capable", "cap_capable", 0)?;
    load_and_attach_program(&mut bpf, "acl_may_open", "may_open", 0)?;
    load_and_attach_program(&mut bpf, "acl_may_create", "may_create", 0)?;
    load_and_attach_program(&mut bpf, "acl_may_delete", "may_delete", 0)?;
    load_and_attach_program(&mut bpf, "acl_may_linkat", "may_linkat", 0)?;
    load_and_attach_program(&mut bpf, "acl_link_path_walk", "link_path_walk", 0)?;
    load_and_attach_program(&mut bpf, "acl_pick_link", "pick_link", 0)?;
    let config_map: Rc<RefCell<Array<MapData, _>>> = Rc::new(RefCell::new(Array::try_from(
        bpf.take_map("NAMESPACE_ID").unwrap(),
    )?));
    let requests: Array<_, Request> = Array::try_from(bpf.map("REQUESTS").unwrap())?;
    let capabilities_map: HashMap<_, Key, u64> =
        HashMap::try_from(bpf.borrow().map("CAPABILITIES_MAP").unwrap())?;
    let pnsid_nsid_map: HashMap<_, Key, u64> =
        HashMap::try_from(bpf.borrow().map("PNSID_NSID_MAP").unwrap())?;
    let uid_gid_map: HashMap<_, Key, u64> =
        HashMap::try_from(bpf.borrow().map("UID_GID_MAP").unwrap())?;
    let ppid_map: HashMap<_, Key, i32> = HashMap::try_from(bpf.map("PPID_MAP").unwrap())?;

    setbpf_effective(false)?;
    setadmin_effective(false)?;
    let mut cli_args = getopt(std::env::args())?;

    {
        if cli_args.daemon || cli_args.command.is_empty() {
            println!("Waiting for Ctrl-C...");
            signal::ctrl_c().await?;
            print_all(
                &capabilities_map,
                &pnsid_nsid_map,
                &uid_gid_map,
                &ppid_map,
                cli_args.json,
            )?;
        } else {
            let nsinode: Rc<RefCell<u32>> = Rc::new(0.into());
            run_command(&mut cli_args, nsinode.clone(), config_map)?;

            print_program_capabilities(
                &nsinode.as_ref().borrow(),
                &capabilities_map,
                &pnsid_nsid_map,
                cli_args.json,
            )
            .expect("failed to print capabilities");
        }
    }
    Ok(())
}
