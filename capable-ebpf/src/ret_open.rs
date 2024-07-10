use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
    macros::map,
    programs::RetProbeContext,
};
use aya_ebpf::maps::Stack;
use crate::ebpf_util::{TaskStructPtr, MAX_PID, is_namespace_ok, get_thread_pid, EPERM};
use crate::open::PENDING_REQUESTS;
use crate::vmlinux::{dentry, file, inode, nameidata, path};
use capable_common::Request;
use aya_log_ebpf::info;

#[map]
static mut REQUESTS: Stack<Request> = Stack::with_max_entries(MAX_PID, 0);


pub fn try_ret_acl_may_action(ctx: &RetProbeContext) -> Result<u32, i64> {
    unsafe {
        if !is_namespace_ok() {
            return Ok(0);
        }
        info!(ctx, "may_action");
            let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
            let task = bpf_probe_read_kernel(&task)?;
            let pid = get_thread_pid(task)?;

            let ret : i32 = ctx.ret().unwrap();

            // if access denied, then find out which user and group can access the file and add it to the UACL_MAP and GACL_MAP
            if ret == -EPERM {
                let request = PENDING_REQUESTS.get(&pid).expect("request not found");
                REQUESTS.push(&request.clone(), 0)?;
            }
            PENDING_REQUESTS.remove(&pid).expect("Impossible");
        }
        Ok(0)

}
