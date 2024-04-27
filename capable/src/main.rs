use std::borrow::Borrow;
use std::cell::RefCell;
use std::error::Error;
use std::fs::{canonicalize, metadata};
use std::os::unix::prelude::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::exit;

use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, thread};

use aya::maps::{HashMap, MapData};
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use capctl::{Cap, CapSet};
use clap::Parser;
use log::{debug, warn};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Uid;
use tabled::settings::object::Columns;

use tabled::settings::{Modify, Style, Width};
use tabled::{Table, Tabled};
use tokio::runtime::Runtime;
use tokio::signal;
use unshare::Signal;

type Key = i32;

#[derive(Parser, Debug)]
#[command(
    about = "Execute command to find out capabilities requests",
    long_about = "sr is a tool to execute privileged commands with a role-based access control system. 
It is designed to be used in a multi-user environment, 
where users can be assigned to different roles, 
and each role has a set of rights to execute commands."
)]

struct Cli {
    /// Specify a delay before killing the process
    #[arg(short, long)]
    sleep: Option<u64>,
    /// collecting data on system and print result at the end
    #[arg(short, long)]
    daemon: bool,
    /// Specify a command to execute with arguments
    command: Vec<String>,
}

#[derive(Tabled)]
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

fn add_dashes() -> Vec<String> {
    //get current argv
    let mut args = std::env::args().collect::<Vec<_>>();
    debug!("args : {:?}", args);
    let mut i = -1;
    //iter through args until we find no dash
    let mut iter = args.iter().enumerate();
    iter.next();
    while let Some((pos, arg)) = iter.next() {
        if arg.starts_with('-') {
            if arg == "-s" {
                iter.next();
            }
            continue;
        } else {
            // add argument at this position
            i = pos as i32;
            break;
        }
    }
    if i > -1 {
        args.insert(i as usize, String::from("--"));
    }
    debug!("final args : {:?}", args);
    args
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
        if graph.contains_key(&ns.0) {
            result = result.union(union_all_childs(ns.0, graph));
        }
    }
    result
}

fn print_program_capabilities<T>(
    nsinode: &u32,
    capabilities_map: &HashMap<T, Key, u64>,
    pnsid_nsid_map: &HashMap<T, Key, u64>,
) -> Result<(), Box<dyn Error>>
where
    T: Borrow<MapData>,
{
    let mut graph = std::collections::HashMap::new();
    let mut init = CapSet::empty();
    for key in capabilities_map.keys() {
        let pid = key?;
        
        let pinum_inum = pnsid_nsid_map.get(&pid, 0).unwrap_or(0);
        let child = pinum_inum as u32;
        let parent = (pinum_inum >> 32) as u32;
        graph.entry(parent).or_insert_with(Vec::new).push((child,caps_from_u64(capabilities_map.get(&pid, 0).unwrap_or(0))));
        if child == *nsinode {
            init = caps_from_u64(capabilities_map.get(&pid, 0).unwrap_or(0));
        }
        
    }
    let result = init.union(union_all_childs(*nsinode, &graph));
    
    
    println!("Here's all capabilities intercepted for this program :\n{}\nWARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\nWARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant",
    capset_to_string(&result));
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
        command[0] = canonicalize(exec_path.clone()).unwrap_or(exec_path).to_str().unwrap().to_string();
        exec_path = PathBuf::from("/bin/sh");
        exec_args = vec!["-c".to_string(), shell_words::join(command)];
    }
    (exec_path, exec_args)
}

fn print_all<T>( capabilities_map: &HashMap<T, Key, u64>, pnsid_nsid_map: &HashMap<T, Key, u64>, uid_gid_map: &HashMap<T, Key, u64>, ppid_map: &HashMap<T, Key, i32>) -> Result<(), anyhow::Error>
where
    T: Borrow<MapData>
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
        println!(
            "\n{}",
            Table::new(&capabilities_table)
                .with(Style::modern())
                .with(Modify::new(Columns::single(3)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::single(2)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::single(6)).with(Width::wrap(10).keep_words()))
                .with(Modify::new(Columns::last()).with(Width::wrap(52).keep_words()))
        );
        Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

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
    let program: &mut KProbe = bpf.program_mut("capable").unwrap().try_into()?;
    program.load()?;
    program.attach("cap_capable", 0)?;

    let args = add_dashes();
    let mut args = Cli::parse_from(args.iter());
    let capabilities_map: HashMap<_, Key, u64> =
        HashMap::try_from(bpf.map("CAPABILITIES_MAP").unwrap())?;
    let pnsid_nsid_map: HashMap<_, Key, u64> =
        HashMap::try_from(bpf.map("PNSID_NSID_MAP").unwrap())?;
    let uid_gid_map: HashMap<_, Key, u64> = HashMap::try_from(bpf.map("UID_GID_MAP").unwrap())?;
    let ppid_map: HashMap<_, Key, i32> = HashMap::try_from(bpf.map("PPID_MAP").unwrap())?;
    if args.daemon || args.command.is_empty() {
        println!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
        print_all(&capabilities_map, &pnsid_nsid_map, &uid_gid_map, &ppid_map)?;
    } else {
        let (path, args) = get_exec_and_args(&mut args.command);
        
        let nsinode: Rc<RefCell<u32>> = Rc::new(0.into());
        let nsclone: Rc<RefCell<u32>> = nsinode.clone();
        let child = Arc::new(Mutex::new(
            unshare::Command::new(path)
                .args(&args)
                .unshare(vec![unshare::Namespace::Pid].iter())
                .before_unfreeze(move |id| {
                    let fnspid = metadata(format!("/proc/{}/ns/pid", id))
                            .expect("failed to open pid ns");
                    nsclone.as_ref().replace(fnspid.ino() as u32);
                    Ok(())
                })
                .spawn()
                .expect("failed to spawn child"),
        ));
        let cloned = child.clone();
        let pid = child.try_lock().unwrap().pid();
        
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(signal::ctrl_c())
                .expect("failed to wait for ctrl-c");
            let nixpid = nix::unistd::Pid::from_raw(pid);
            nix::sys::signal::kill(nixpid, nix::sys::signal::Signal::SIGINT)
                .expect("failed to send SIGINT");
            let mut i = 0;
            if nix::sys::wait::waitpid(nixpid, Some(WaitPidFlag::WNOHANG))
                .expect("Fail to wait pid")
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
                    .signal(Signal::SIGKILL)
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
        
        cloned
            .try_lock()
            .unwrap()
            .wait()
            .expect("failed to wait on child");
        //print_all(&capabilities_map, &pnsid_nsid_map, &uid_gid_map, &ppid_map)?;
        print_program_capabilities(&nsinode.as_ref().borrow(), &capabilities_map, &pnsid_nsid_map)
            .expect("failed to print capabilities");
    }

    Ok(())
}
