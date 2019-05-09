#include <linux/filter.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") capabilities_map = {
	.type = 		BPF_MAP_TYPE_HASH,
	.key_size 		= sizeof(u32),
	.value_size		= sizeof(u64),
	.max_entries	= PID_MAX_DEFAULT,
	.map_flags   	= 0
};

SEC("kprobe/capable")
int bpf_prog1(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
	u64 cap = (u64)PT_REGS_PARM1(ctx); // param 1 is capability
	u64 *val = bpf_map_lookup_elem(&capabilities_map, &pid);
	u64 initial = 0;
	//u32 uid = bpf_get_current_uid_gid();
	//unsigned long unknown1 = PT_REGS_PARM2(ctx); //???
	//unsigned long unknown2 = PT_REGS_PARM3(ctx); //???
	
	
	if(val){
		*val |= cap;
	}else{
		bpf_map_update_elem(&capabilities_map, &pid, &initial, BPF_ANY);
	}
	
	
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
