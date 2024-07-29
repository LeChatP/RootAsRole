use core::ffi::{c_long, c_void};
use core::mem;
use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
    macros::map,
    maps::HashMap,
    programs::ProbeContext,
};
use aya_ebpf::helpers::gen::bpf_probe_read_kernel_str;
use aya_ebpf::maps::LruPerCpuHashMap;
use aya_log_ebpf::{debug, info, warn};
use crate::ebpf_util::{TaskStructPtr, is_namespace_ok, MAX_PID, get_thread_pid};
use crate::vmlinux::{dentry, nameidata, path, pid};
use capable_common::{Access, FILENAME_SIZE, MAX_REQUESTS, PATH_SIZE, Request};
pub type DentryPtr = *mut dentry;
pub type PathPtr = *mut path;
pub type NameidataPtr = *mut nameidata;
pub type PidPtr = *mut pid;

#[map]
pub static mut PENDING_REQUESTS: LruPerCpuHashMap<u64, Request> = LruPerCpuHashMap::with_max_entries(MAX_REQUESTS, 0);


pub fn try_acl_may_create(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_create");
    let dentry = unsafe { ctx.arg::<DentryPtr>(2).expect("DentryPtr should be here") };

    /*try_acl_may_action(
        ctx,
        dentry,
        Access::CREATE,
    )*/
    Ok(0)
}

pub fn try_acl_may_open(ctx: &ProbeContext) -> Result<u32, i64> {
    //info!(ctx, "may_open");
    let dentry = unsafe { get_dentry_from_pathptr(ctx.arg::<PathPtr>(1).expect("PathPtr should be here"))? };

    //debug!(ctx,"d_name : {}", str);
    //info!(ctx, "may_open dentry");
    //let access = Access::from_bits(ctx.arg::<u32>(2).expect("bits")).expect("Should be valid Access type") | Access::OPEN;
    //info!(ctx, "may_open access");
    /**try_acl_may_action(
        ctx,
        dentry,
        access,
    )*/
    Ok(0)
}

pub fn try_acl_may_delete(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_delete");
    /*try_acl_may_action(
        ctx,
        unsafe { ctx.arg::<DentryPtr>(2).expect("DentryPtr should be here") },
        Access::DELETE,
    )*/
    Ok(0)
}

pub fn try_acl_may_linkat(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_linkat");
    /*try_acl_may_action(
        ctx,
        unsafe { get_dentry_from_pathptr(ctx.arg::<PathPtr>(2).expect("PathPtr should be here"))? },
        Access::LINKAT,
    )*/
    Ok(0)
}

pub fn try_acl_may_link_path_walk(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_link_path_walk");
    /*try_acl_may_action(
        ctx,
        unsafe { get_dentry_from_nameidata(ctx.arg::<NameidataPtr>(1).expect("Nameidata should be here"))? },
        Access::LOOKUP,
    )*/
    Ok(0)
}

pub fn try_acl_pick_link(ctx: &ProbeContext) -> Result<u32, i64> {
    info!(ctx, "may_pick_link");
    /*try_acl_may_action(
        ctx,
        unsafe { get_dentry_from_nameidata(ctx.arg::<NameidataPtr>(0).expect("Nameidata should be here"))? },
        Access::FOLLOW_LINK,
    )*/
    Ok(0)
}

const LOOP_MAX: u32 = 25;

unsafe fn get_dentry_from_pathptr(path: PathPtr) -> Result<DentryPtr, i64> {
    let path1 = bpf_probe_read_kernel(&path)?;
    Ok(bpf_probe_read_kernel(&(*path1).dentry)?)
}

unsafe fn get_dentry_from_nameidata(path: NameidataPtr) -> Result<DentryPtr, i64> {
    get_dentry_from_pathptr(&mut (*bpf_probe_read_kernel(&path)?).path)
}

fn read_kernel_str_as_result(res : c_long) -> Result<usize, i64> {
    if res < 0 {
        Err(res as i64)
    } else {
        Ok(res as usize)
    }
}

unsafe fn get_full_path(dentry: DentryPtr, result: *mut [u8; PATH_SIZE]) -> Result<(), i64> {
    let dname = unsafe { bpf_probe_read_kernel(&(*dentry).d_name)? };
    let name = unsafe { bpf_probe_read_kernel(&dname.name)? };
    let mut length = unsafe { read_kernel_str(result as *mut c_void, FILENAME_SIZE as u32, name as *mut c_void)? };

    //convert path_str as &str
    let mut super_block = bpf_probe_read_kernel(&(*dentry).d_sb)?;
    let root = bpf_probe_read_kernel(&(*super_block).s_root)? as DentryPtr;

    let mut i = 0;
    let mut parent: DentryPtr = bpf_probe_read_kernel(&(*dentry).d_parent)?;
    while length < PATH_SIZE || dentry != root {
        (*result)[length] = b'/';
        length += 1;
        let dname = unsafe { bpf_probe_read_kernel(&(*parent).d_name)? };
        let name = unsafe { bpf_probe_read_kernel(&dname.name)? };
        length += read_kernel_str((*result)[length] as *mut c_void, (FILENAME_SIZE - length) as u32, name as *mut c_void)?;
        parent = bpf_probe_read_kernel(&(*parent).d_parent)?;
        i += 1;
    }
    (*result)[length] = b'/';
    length += 1;
    Ok(())
}

unsafe fn input_request(key: u64, dentry: DentryPtr, mode: Access) -> Result<(), i64> {
    //allocate to heap a Request type


    match PENDING_REQUESTS.get_ptr_mut(&key).and_then(|ptr| unsafe { ptr.as_mut() }) {
        None => Err(-1),
        Some(request) => {
            get_full_path(dentry, &mut request.f_path)?;
            (*request).f_mode = mode;
            return Ok(());
        }
    }

    //let request = PENDING_REQUESTS.get_ptr_mut(&key).unwrap();
    //get_full_path(dentry, &mut ((*request).f_path))?;
}

fn try_acl_may_action(ctx: &ProbeContext, dentry: DentryPtr, mode: Access) -> Result<u32, i64> {
    unsafe {
        if !is_namespace_ok() {
            return Ok(0);
        }
        info!(ctx, "may_action");
        let task: TaskStructPtr = bpf_get_current_task() as TaskStructPtr;
        let pid = get_thread_pid(task)?;
        input_request(pid, dentry, mode).map(|_| 0)
    }
}

unsafe fn get_path_str_ptr(dentry: DentryPtr) -> Result<*mut c_void, i64> {
    Ok(bpf_probe_read_kernel(bpf_probe_read_kernel(&(*dentry).d_name)?.name)? as *mut c_void)
}
fn result_kernel_str(result: c_long) -> Result<usize, i64> {
    if result < 0 {
        Err(result as i64)
    } else {
        Ok(result as usize)
    }
}

fn read_kernel_str(dest: *mut c_void, size: u32, src: *mut c_void) -> Result<usize, i64> {
    result_kernel_str(unsafe { bpf_probe_read_kernel_str(dest, size, src) })
}
