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
struct bpf_map_def SEC("maps") ppid_map = {
	.type = 		BPF_MAP_TYPE_HASH,
	.key_size 		= sizeof(u32),
	.value_size		= sizeof(u32),
	.max_entries	= PID_MAX_DEFAULT,
	.map_flags   	= 0
};

int get_ppid(struct task_struct *task) 
{
    u32 ppid; 
    struct task_struct *parent; 
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent); 
    bpf_probe_read(&ppid, sizeof(ppid), &parent->pid); 
    return ppid; 
} 

SEC("kprobe/capable")
int bpf_prog1(struct pt_regs *ctx)
{
	u32 ppid = get_ppid((struct task_struct*)bpf_get_current_task());
    u32 pid = bpf_get_current_pid_tgid() >> 32; // >>32 to get tgid
	u32 cap = (u32)PT_REGS_PARM1(ctx); // param 1 is capability
	u64 *capval = bpf_map_lookup_elem(&capabilities_map, &pid);
	u64 initial = ((u64) 1 << cap);
	//unsigned long unknown1 = PT_REGS_PARM2(ctx); //???
	//unsigned long unknown2 = PT_REGS_PARM3(ctx); //???
	char fmt[] = "| %d\t| %d\t| %d\t|";
	bpf_trace_printk(fmt,sizeof(fmt),pid,ppid,cap);
	if(capval){
		*capval |= initial ;
	}else{
		bpf_map_update_elem(&ppid_map, &pid, &ppid, BPF_ANY);
		bpf_map_update_elem(&capabilities_map, &pid, &initial, BPF_ANY);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
