use core::ffi::{c_long, c_void};
use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
    macros::map,
    maps::HashMap,
    programs::ProbeContext,
};
use aya_ebpf::helpers::gen::bpf_probe_read_kernel_str;
use aya_log_ebpf::info;
use crate::ebpf_util::{TaskStructPtr, is_namespace_ok, MAX_PID, get_thread_pid};
use crate::vmlinux::{dentry, nameidata, path, pid};
use capable_common::{Access, Request};
pub type DentryPtr = *mut dentry;
pub type PathPtr = *mut path;
pub type NameidataPtr = *mut nameidata;
pub type PidPtr = *mut pid;

#[map]
pub static mut PENDING_REQUESTS: HashMap<u64, Request> = HashMap::with_max_entries(MAX_PID, 0);



pub fn try_acl_may_create(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_create");
    try_acl_may_action(
        ctx,
        Request {
            f_path: unsafe { get_full_path(ctx.arg::<DentryPtr>(2).expect("DentryPtr should be here"))? },
            f_mode: Access::CREATE,
        },
    )
}

pub fn try_acl_may_open(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_open");
    try_acl_may_action(
        ctx,
        Request {
            f_path: unsafe { get_full_path(get_dentry_from_pathptr(*ctx.arg::<PathPtr>(1).expect("PathPtr should be here"))?)? },
            f_mode: Access::from_bits(ctx.arg::<u32>(2).expect("bits")).expect("Should be valid Access type") | Access::OPEN,
        },
    )
}

pub fn try_acl_may_delete(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_delete");
    try_acl_may_action(
        ctx,
        Request {
            f_path: unsafe { get_full_path(ctx.arg::<DentryPtr>(2).expect("DentryPtr should be here"))? },
            f_mode: Access::DELETE,
        },
    )
}

pub fn try_acl_may_linkat(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_linkat");
    try_acl_may_action(
        ctx,
        Request {
            f_path: unsafe { get_full_path(get_dentry_from_pathptr(*ctx.arg::<PathPtr>(2).expect("PathPtr should be here"))?)? },
            f_mode: Access::LINKAT,
        },
    )
}

pub fn try_acl_may_lookup(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_lookup");
    try_acl_may_action(
        ctx,
        Request {
            f_path: unsafe {
                get_full_path(get_dentry_from_nameidata(ctx.arg::<NameidataPtr>(1).expect("Nameidata should be here"))?)?
            },
            f_mode: Access::LOOKUP,
        },
    )
}

pub fn try_acl_may_follow_link(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_follow_link");
    try_acl_may_action(
        ctx,
        Request {
            f_path: unsafe {
                get_full_path(get_dentry_from_nameidata(ctx.arg::<NameidataPtr>(0).expect("Nameidata should be here"))?)?
            },
            f_mode: Access::FOLLOW_LINK,
        },
    )
}

const LOOP_MAX: u32 = 25;

unsafe fn get_dentry_from_pathptr(path: path) -> Result<DentryPtr, i64> {
    bpf_probe_read_kernel(&path.dentry)
}

unsafe fn get_dentry_from_nameidata(path: NameidataPtr) -> Result<DentryPtr, i64> {
    get_dentry_from_pathptr(bpf_probe_read_kernel(&(*path).path)?)
}

const SIZE: usize = 8188;
unsafe fn get_full_path(dentry: DentryPtr) -> Result<[u8;SIZE], i64> {
    let mut result = [0u8; SIZE];
    let mut length = read_kernel_str(result[0] as *mut c_void, SIZE as u32, get_path_str_ptr(dentry)?)?;
    let mut parent: DentryPtr = bpf_probe_read_kernel(&(*dentry).d_parent)?;
    let mut i = 0;
    while length < 8187 || parent != 0 as DentryPtr || LOOP_MAX < i {
        result[length] = b'/';
        length += 1;
        length += read_kernel_str(result[length] as *mut c_void, (SIZE - length) as u32, get_path_str_ptr(parent)?)?;
        parent = bpf_probe_read_kernel(&(*parent).d_parent)?;
        i += 1;
    }
    Ok(result)
}

fn try_acl_may_action(ctx: &ProbeContext, request: Request) -> Result<u32, i64> {
    unsafe {
        if !is_namespace_ok() {
            return Ok(0);
        }
        info!(ctx, "may_action");
        let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let task = bpf_probe_read_kernel(&task)?;
        let pid = get_thread_pid(task)?;

        // if access denied, then find out which user and group can access the file and add it to the UACL_MAP and GACL_MAP
        PENDING_REQUESTS.insert(&pid,&request,0).expect("failed to insert request");
        Ok(0)
    }
}

unsafe fn get_path_str_ptr(dentry: DentryPtr) -> Result<*mut c_void, i64> {
    Ok(bpf_probe_read_kernel(bpf_probe_read_kernel(&(*dentry).d_name)?.name)? as *mut c_void)
}
fn result_kernel_str(result : c_long) -> Result<usize, i64> {
    if result < 0 {
        Err(result as i64)
    } else {
        Ok(result as usize)
    }
}

fn read_kernel_str(dest: *mut c_void, size: u32, src: *mut c_void) -> Result<usize, i64> {
    result_kernel_str(unsafe { bpf_probe_read_kernel_str(dest, size, src) })
}
