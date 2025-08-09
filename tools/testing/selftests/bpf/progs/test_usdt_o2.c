// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

int my_pid;

int usdt_sib_called;
u64 usdt_sib_cookie;
int usdt_sib_arg_cnt;
int usdt_sib_arg_ret;
u64 usdt_sib_arg;
int usdt_sib_arg_size;

SEC("usdt")
int usdt_sib(struct pt_regs *ctx)
{
	long tmp;

	if (my_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	__sync_fetch_and_add(&usdt_sib_called, 1);

	usdt_sib_cookie = bpf_usdt_cookie(ctx);
	usdt_sib_arg_cnt = bpf_usdt_arg_cnt(ctx);

	usdt_sib_arg_ret = bpf_usdt_arg(ctx, 0, &tmp);
	usdt_sib_arg = (u64)tmp;
	usdt_sib_arg_size = bpf_usdt_arg_size(ctx, 0);

	return 0;
}

int usdt_rip_called;
u64 usdt_rip_cookie;
int usdt_rip_arg_cnt;
int usdt_rip_arg_rets[3];
u64 usdt_rip_args[3];
int usdt_rip_arg_sizes[3];

SEC("usdt//proc/self/exe:test:usdt_rip")
int usdt_rip(struct pt_regs *ctx)
{
	long tmp;

	if (my_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	__sync_fetch_and_add(&usdt_sib_called, 1);

	usdt_rip_cookie = bpf_usdt_cookie(ctx);
	usdt_rip_arg_cnt = bpf_usdt_arg_cnt(ctx);

	usdt_rip_arg_rets[0] = bpf_usdt_arg(ctx, 0, &tmp);
	usdt_rip_args[0] = (char)tmp;
	usdt_rip_arg_sizes[0] = bpf_usdt_arg_size(ctx, 0);

	usdt_rip_arg_rets[1] = bpf_usdt_arg(ctx, 1, &tmp);
	usdt_rip_args[1] = (long)tmp;
	usdt_rip_arg_sizes[1] = bpf_usdt_arg_size(ctx, 1);

	usdt_rip_arg_rets[2] = bpf_usdt_arg(ctx, 2, &tmp);
	usdt_rip_args[2] = (uintptr_t)tmp;
	usdt_rip_arg_sizes[2] = bpf_usdt_arg_size(ctx, 2);

	return 0;
}

char _license[] SEC("license") = "GPL";
