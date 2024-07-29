#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

mod capable;
mod open;
pub mod ebpf_util;
mod ret_open;

use aya_ebpf::{
    macros::{kretprobe, kprobe},
    programs::{RetProbeContext, ProbeContext},
};
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;
use aya_log_ebpf::info;
use crate::capable::try_capable;
use crate::open::{try_acl_may_create, try_acl_may_open, try_acl_may_delete, try_acl_may_linkat, try_acl_pick_link};
use crate::ret_open::try_ret_acl_may_action;

#[kprobe]
pub fn acl_may_open(ctx: ProbeContext) -> u32 {
    info!(&ctx, "may_open_kprobe");
    try_acl_may_open(&ctx).unwrap_or_else(|ret| ret as u32)
}

#[kprobe]
pub fn acl_may_create(ctx: ProbeContext) -> u32 {
    try_acl_may_create(&ctx).unwrap_or_else(|ret| ret as u32)
}

#[kprobe]
pub fn acl_may_delete(ctx: ProbeContext) -> u32 {
   // try_acl_may_delete(&ctx).unwrap_or_else(|ret| ret as u32)
    0
}

#[kprobe]
pub fn acl_may_linkat(ctx: ProbeContext) -> u32 {
    //try_acl_may_linkat(&ctx).unwrap_or_else(|ret| ret as u32)
    0
}

#[lsm(hook = "")]
pub fn acl_link_path_walk(ctx: ProbeContext) -> u32 {
    // try_acl_may_link_path_walk(&ctx).unwrap_or_else(|ret| ret as u32)
    0
}

#[kprobe]
pub fn acl_pick_link(ctx: ProbeContext) -> u32 {
    // try_acl_may_follow_link(&ctx).unwrap_or_else(|ret| ret as u32)
    0
}

#[kretprobe]
pub fn acl_may_ret(ctx: RetProbeContext) -> u32 {
    // try_ret_acl_may_action(&ctx).unwrap_or_else(|ret| ret as u32)
    0
}

#[kprobe]
pub fn capable(ctx: ProbeContext) -> u32 {
    try_capable(&ctx).unwrap_or_else(|ret| ret as u32)
}

// as we want to hook every acl requests, we need to obtain every acl modification requests.
#[lsm(hook = "inode_set_acl")]
pub fn bpf_lsm_change_acl(ctx: LsmContext) -> i32 {
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
