#include <linux/filter.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include "bpf_helpers.h"

#define PERF_MAX_STACK_DEPTH         127

struct bpf_map_def SEC("maps") capabilities_map = { .type = BPF_MAP_TYPE_HASH,
					 .key_size = sizeof(__u64),
					 .value_size = sizeof(__u64),
					 .max_entries = PID_MAX_DEFAULT,
					 .map_flags = 0 };
struct bpf_map_def SEC("maps") uid_gid_map = { .type = BPF_MAP_TYPE_HASH,
					    .key_size = sizeof(__u64),
					    .value_size = sizeof(__u64),
					    .max_entries = PID_MAX_DEFAULT,
					    .map_flags = 0 };

struct bpf_map_def SEC("maps") stackmap = { .type = BPF_MAP_TYPE_STACK_TRACE,
						.key_size = sizeof(__u64),
						.value_size = sizeof(__u64) * PERF_MAX_STACK_DEPTH,
						.max_entries = 128 };

int get_ppid(struct task_struct *task)
{
	u32 ppid;
	struct task_struct *parent;
	bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
	bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
	return ppid;
}

SEC("kprobe/cap_capable")
int bpf_cap_capable(struct pt_regs *ctx)
{
	u64 pid_ppid = (get_ppid((struct task_struct *)bpf_get_current_task())) | (bpf_get_current_pid_tgid() & (u64)0xffffffff00000000);
	u32 cap = (u32)PT_REGS_PARM3(ctx); // param 1 is capability
	u64 uid_gid = bpf_get_current_uid_gid();
	u64 *capval = bpf_map_lookup_elem(&capabilities_map, &uid_gid);
	//void *buf;
	//int stacksize = bpf_get_stack(ctx,buf,sizeof(__u64) * PERF_MAX_STACK_DEPTH,0); //analyze stacktrace for fork()
	u64 initial = ((u64)1 << cap); // if cap_sys_ressource or cap_sys_admin called first
	char fmt[] = "| %d\t| %d\t| %d\t|\n";
	bpf_trace_printk(fmt, sizeof(fmt), (u32)(pid_ppid>>32), (u32)pid_ppid, cap);
	if (capval) {
		*capval |= initial;
	} else {
		bpf_map_update_elem(&uid_gid_map, &pid_ppid, &uid_gid, BPF_ANY);
		bpf_map_update_elem(&capabilities_map, &pid_ppid, &initial, BPF_ANY);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
