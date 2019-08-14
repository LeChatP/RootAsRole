#include <linux/filter.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/pid_namespace.h>
#include "bpf_helpers.h"

//#define randomized_struct_fields_start  struct {
//#define randomized_struct_fields_end    };

#define MAX_STACK_RAWTP 5

/**
 * this eBPF will listen to cap_capable() kprobe
 * will store capabilities asked referenced by namespace inum
 * will retrieve parent namespace inum
 * will blacklist capabilities if stack address is in blacklist
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
struct bpf_map_def SEC("maps") parent_map = { .type = BPF_MAP_TYPE_HASH, //current namespace inode
						.key_size = sizeof(__u32),
						.value_size = sizeof(__u32),
						.max_entries = PID_MAX_DEFAULT,
						.map_flags = 0 };

struct task_struct *get_parent_task(struct task_struct *task){
	struct task_struct *parent;
	bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
	return parent;
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
int bpf_cap_capable_ns(struct pt_regs *ctx)
{
	int i = 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task(); //getting actual task
	u32 cap = (u32)PT_REGS_PARM3(ctx), // this param is capability
		inum = get_ns_inode(task), // get inode of current namespace 
		*pinum = bpf_map_lookup_elem(&parent_map, &inum); //getting parent inode pointer
	u64 *capval = bpf_map_lookup_elem(&capabilities_map, &inum), // getting ancient capabilities value
		initial = ((u64)1 << cap); //transform capability to bit position
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
	#endif K50
	if (capval) {
		*capval |= initial; // update value if existing
	} else {
		bpf_map_update_elem(&capabilities_map, &inum, &initial, BPF_ANY); //save first capability
	}
	if(!pinum){ // if parent isn't existing
		unsigned int parent_inum = get_parent_ns_inode(task); //getting parent
		if(parent_inum !=inum) //if parent namespace getted is equal actual namespace, then we are too depth, theorically impossible
			bpf_map_update_elem(&parent_map, &inum, &parent_inum, BPF_ANY); //save parent
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
