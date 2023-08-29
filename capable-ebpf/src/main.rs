#![no_std]
#![no_main]


#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{macros::{kprobe,map}, maps::HashMap, programs::ProbeContext, helpers::{bpf_get_current_task, bpf_get_current_uid_gid, bpf_probe_read_kernel}};
use vmlinux::{task_struct, nsproxy, pid_namespace, ns_common};

const MAX_PID : u32 = 4*1024*1024;

type Key = i32;
type task_struct_ptr = *mut task_struct;

#[map]
static KALLSYMS_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID,0);
#[map]
static CAPABILITIES_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID,0);
#[map]
static UID_GID_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID,0);
#[map]
static PPID_MAP: HashMap<Key, i32> = HashMap::with_max_entries(MAX_PID,0);
#[map]
static PNSID_NSID_MAP: HashMap<Key, u64> = HashMap::with_max_entries(MAX_PID,0);

#[kprobe]
pub fn capable(ctx: ProbeContext) -> u32 {
    match try_capable(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_capable(ctx: ProbeContext) -> Result<u32, i64> {
    unsafe {
        let task: task_struct_ptr = bpf_get_current_task() as task_struct_ptr;
        let task = bpf_probe_read_kernel(&task)?;
        let ppid: i32 = get_ppid(task)?;
        let pid: i32 = bpf_probe_read_kernel(&(*task).pid)?;
        let cap: u64 = ctx.arg(3).unwrap();
        let uid: u64 = bpf_get_current_uid_gid();
        let capval = CAPABILITIES_MAP.get_ptr_mut(&pid).unwrap_or(&mut 0);
        let pinum_inum :u64 = Into::<u64>::into(get_parent_ns_inode(task)?)<<32 | Into::<u64>::into(get_ns_inode(task)?);
        UID_GID_MAP.insert(&pid, &uid,0).expect("failed to insert uid");
        PNSID_NSID_MAP.insert(&pid, &pinum_inum,0).expect("failed to insert pnsid");
        PPID_MAP.insert(&pid, &ppid,0).expect("failed to insert ppid");
        *capval |= cap;
        CAPABILITIES_MAP.insert(&pid, &*capval,0).expect("failed to insert cap");
    }
    Ok(0)
}

unsafe fn get_ppid(task : task_struct_ptr) -> Result<i32, i64> {
    let parent_task: task_struct_ptr = get_parent_task(task)?;
    return bpf_probe_read_kernel(&(*parent_task).pid);
}

unsafe fn get_parent_task(task : task_struct_ptr) -> Result<task_struct_ptr, i64> {
    return bpf_probe_read_kernel(&(*task).real_parent);
}

unsafe fn get_parent_ns_inode(task : task_struct_ptr) -> Result<u32, i64> {
    let parent_task: task_struct_ptr = get_parent_task(task)?;
    return get_ns_inode(parent_task);
}

unsafe fn get_ns_inode(task : task_struct_ptr) -> Result<u32, i64> {
    let nsp: *mut nsproxy  = bpf_probe_read_kernel(&(*task).nsproxy)?;
    let pns: *mut pid_namespace = bpf_probe_read_kernel(&(*nsp).pid_ns_for_children)?;
    let nsc: ns_common = bpf_probe_read_kernel(&(*pns).ns)?;
    return bpf_probe_read_kernel(&nsc.inum);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
