#include <linux/filter.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/pid_namespace.h>
#include "bpf_helpers.h"

#define MAX_STACK_RAWTP 5

/**
 * This eBPF still useful for daemon analysis
 */
struct bpf_map_def SEC("maps") kallsyms_map = { .type = BPF_MAP_TYPE_HASH,
						.key_size = sizeof(__u32),
						.value_size = sizeof(__u64),
						.max_entries = PID_MAX_DEFAULT,
						.map_flags = 0 };
struct bpf_map_def SEC("maps") capabilities_map = { .type = BPF_MAP_TYPE_HASH,
						.key_size = sizeof(__u32),
						.value_size = sizeof(__u64),
						.max_entries = PID_MAX_DEFAULT,
						.map_flags = 0 };
struct bpf_map_def SEC("maps") uid_gid_map = { .type = BPF_MAP_TYPE_HASH,
					    .key_size = sizeof(__u32),
					    .value_size = sizeof(__u64),
					    .max_entries = PID_MAX_DEFAULT,
					    .map_flags = 0 };
struct bpf_map_def SEC("maps") ppid_map = { .type = BPF_MAP_TYPE_HASH,
						.key_size = sizeof(__u32),
						.value_size = sizeof(__u32),
						.max_entries = PID_MAX_DEFAULT,
						.map_flags = 0 };
struct bpf_map_def SEC("maps") pnsid_nsid_map = { .type = BPF_MAP_TYPE_HASH,
						.key_size = sizeof(__u32),
						.value_size = sizeof(__u64),
						.max_entries = PID_MAX_DEFAULT,
						.map_flags = 0 };

struct task_struct *get_parent_task(struct task_struct *task){
	struct task_struct *parent;
	bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
	return parent;
}

int get_ppid(struct task_struct *task)
{
	u32 ppid;
	struct task_struct *parent = get_parent_task(task);
	bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
	return ppid;
}

unsigned int get_ns_inode(struct task_struct *task){
	struct nsproxy *nsp;
	struct pid_namespace *pns;
	struct ns_common nsc;
	unsigned int inum;
	bpf_probe_read(&nsp,sizeof(nsp),&task->nsproxy);
	bpf_probe_read(&pns,sizeof(pns),&nsp->pid_ns_for_children);
	bpf_probe_read(&nsc,sizeof(nsc),&pns->ns);
	return nsc.inum;
}
/**
 * return parent ns inum if same ns returned, it's because parent pid is the same
 */
unsigned int get_parent_ns_inode(struct task_struct *task){
	struct task_struct *parent = get_parent_task(task);
	return get_ns_inode(parent);
}

SEC("kprobe/cap_capable")
int bpf_cap_capable(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 ppid = get_ppid(task);
	int i = 0;
	u32 pid = bpf_get_current_pid_tgid()>>32;
	u64	cap = (u64)PT_REGS_PARM3(ctx),
		uid_gid = bpf_get_current_uid_gid(),
		*capval = bpf_map_lookup_elem(&capabilities_map, &pid),
	    pinum_inum = ((u64)get_parent_ns_inode(task)<<32) | get_ns_inode(task),
		initial = ((u64)1 << cap); // if cap_sys_ressource or cap_sys_admin called first
	#ifdef K50
	u64	userstack[MAX_STACK_RAWTP], //store current stack addresses
		*blacklist_stack = bpf_map_lookup_elem(&kallsyms_map, &i); //getting first entry of blacklist kernel stack call
	bpf_get_stack(ctx,userstack,sizeof(u64)*MAX_STACK_RAWTP,0); // retrieve MAX_STACK_RAWTP kernel stack calls
	if(blacklist_stack){ // if blacklist exist, then check in stack with MAX_STACK_RAWTP depth for the call
		// loops are forbidden in eBPF
		if(userstack[0] == *blacklist_stack)
			initial = 0; // if blacklist found then ignore capability but still write entry to map
		else if(userstack[1] == *blacklist_stack) 
			initial = 0;
		else if(userstack[2] == *blacklist_stack) 
			initial = 0;
		else if(userstack[3] == *blacklist_stack) 
			initial = 0;
		else if(userstack[4] == *blacklist_stack) 
			initial = 0;
	}
	#endif
	if (capval) {
		*capval |= initial;
	} else {
		bpf_map_update_elem(&uid_gid_map, &pid, &uid_gid, BPF_ANY);
		bpf_map_update_elem(&pnsid_nsid_map, &pid, &pinum_inum, BPF_ANY);
		bpf_map_update_elem(&ppid_map, &pid, &ppid, BPF_ANY);
		bpf_map_update_elem(&capabilities_map, &pid, &initial, BPF_ANY);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
