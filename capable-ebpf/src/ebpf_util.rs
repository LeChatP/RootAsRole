use aya_ebpf::{
    helpers::{bpf_probe_read_kernel,bpf_get_current_task},
    macros::map,
    maps::array::Array,
};
use crate::open::PidPtr;
use crate::vmlinux::{ns_common, nsproxy, pid_namespace, task_struct};

#[map]
static mut NAMESPACE_ID: Array<u32> = Array::with_max_entries(1, 0);

pub unsafe fn is_namespace_ok() -> bool {
    NAMESPACE_ID.get(0).map_or(false,|namespace| {
        let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let current_namespace = get_ns_inode(task);
        current_namespace.ok().map_or(false, |ns| ns == *namespace)
    })
}

pub type TaskStructPtr = *mut task_struct;
pub const MAX_PID: u32 = 4 * 1024 * 1024;
pub const EPERM : i32 = 1;

pub unsafe fn get_thread_pid(task: TaskStructPtr) -> Result<u64, i64> {
    let pid: PidPtr = bpf_probe_read_kernel(&(*task).thread_pid)? as PidPtr;
    let pid = bpf_probe_read_kernel(&(*pid).ino)? as u64;
    Ok(pid)
}

pub unsafe fn get_ns_inode(task: TaskStructPtr) -> Result<u32, i64> {
    let nsp: *mut nsproxy = bpf_probe_read_kernel(&(*task).nsproxy).map_err(|e| e as u32)?;
    let pns: *mut pid_namespace =
        bpf_probe_read_kernel(&(*nsp).pid_ns_for_children).map_err(|e| e as u32)?;
    let nsc: ns_common = bpf_probe_read_kernel(&(*pns).ns).map_err(|e| e as u32)?;
    bpf_probe_read_kernel(&nsc.inum)
}