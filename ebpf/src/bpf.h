/*
 * common eBPF ELF operations.
 *
 * Copyright (C) 2013-2015 Alexei Starovoitov <ast@kernel.org>
 * Copyright (C) 2015 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015 Huawei Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 */
#ifndef __BPF_BPF_H
#define __BPF_BPF_H

#include <linux/bpf.h>

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
		   int max_entries, __u32 map_flags);

/* Recommend log buffer size */
#define BPF_LOG_BUF_SIZE 65536
int bpf_load_program(enum bpf_prog_type type, struct bpf_insn *insns,
		     size_t insns_cnt, char *license,
		     __u32 kern_version, char *log_buf,
		     size_t log_buf_sz);

int bpf_map_update_elem(int fd, void *key, void *value,
			__u64 flags);

int bpf_map_lookup_elem(int fd, void *key, void *value);
int bpf_map_delete_elem(int fd, void *key);
int bpf_map_get_next_key(int fd, void *key, void *next_key);
int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);
int bpf_prog_attach(int prog_fd, int attachable_fd, enum bpf_attach_type type,
		    unsigned int flags);
int bpf_prog_detach(int attachable_fd, enum bpf_attach_type type);


#endif