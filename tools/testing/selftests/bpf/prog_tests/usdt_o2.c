// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Jiawei Zhao <phoenix500526@163.com>. */
#include <test_progs.h>

#define _SDT_HAS_SEMAPHORES 1
#include "../sdt.h"
#include "test_usdt_o2.skel.h"

int lets_test_this(int);

#define test_value 0xFEDCBA9876543210ULL
#define SEC(name) __attribute__((section(name), used))

static volatile __u64 array[1] = {test_value};
unsigned short test_usdt_sib_semaphore SEC(".probes");
unsigned short test_usdt_rip_semaphore SEC(".probes");

static volatile struct st{
	char a;
	long b;
};

static volatile struct st ti = {.a = 'a', .b = 1024};
static volatile char c = 'b';

int add(int a, int b) {
  return a + b;
}

int (*add_ptr)(int, int) = add;

static __always_inline void trigger_func(void)
{
	/* Base address + offset + (index * scale) */
	if (test_usdt_sib_semaphore) {
		for (volatile int i = 0; i <= 0; i++)
			STAP_PROBE1(test, usdt_sib, array[i]);
	}

	if (test_usdt_rip_semaphore) {
		STAP_PROBE3(test, usdt_rip, c, ti.b, add_ptr);
	}

}

static void basic_usdt(void)
{
	LIBBPF_OPTS(bpf_usdt_opts, opts);
	struct test_usdt_o2 *skel;
	struct test_usdt_o2__bss *bss;
	int err;

	skel = test_usdt_o2__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bss = skel->bss;
	bss->my_pid = getpid();

	err = test_usdt_o2__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* usdt_sib won't be auto-attached */
	opts.usdt_cookie = 0xcafedeadbeeffeed;
	skel->links.usdt_sib = bpf_program__attach_usdt(skel->progs.usdt_sib,
						     0 /*self*/, "/proc/self/exe",
						     "test", "usdt_sib", &opts);
	if (!ASSERT_OK_PTR(skel->links.usdt_sib, "usdt_sib_link"))
		goto cleanup;

	trigger_func();

	ASSERT_EQ(bss->usdt_sib_called, 1, "usdt_sib_called");
	ASSERT_EQ(bss->usdt_sib_cookie, 0xcafedeadbeeffeed, "usdt_sib_cookie");
	ASSERT_EQ(bss->usdt_sib_arg_cnt, 1, "usdt_sib_arg_cnt");
	ASSERT_EQ(bss->usdt_sib_arg, test_value, "usdt_sib_arg");
	ASSERT_EQ(bss->usdt_sib_arg_ret, 0, "usdt_sib_arg_ret");
	ASSERT_EQ(bss->usdt_sib_arg_size, sizeof(array[0]), "usdt_sib_arg_size");

	/* auto-attached usdt_rip gets default zero cookie value */
	ASSERT_EQ(bss->usdt_rip_cookie, 0, "usdt_rip_cookie");
	ASSERT_EQ(bss->usdt_rip_arg_cnt, 3, "usdt_rip_arg_cnt");
	ASSERT_EQ(bss->usdt_rip_arg_rets[0], 0, "usdt_rip_arg1_ret");
	ASSERT_EQ(bss->usdt_rip_arg_rets[1], 0, "usdt_rip_arg2_ret");
	ASSERT_EQ(bss->usdt_rip_arg_rets[2], 0, "usdt_rip_arg3_ret");
	ASSERT_EQ(bss->usdt_rip_args[0], c, "usdt_rip_arg1");
	ASSERT_EQ(bss->usdt_rip_args[1], ti.b, "usdt_rip_arg2");
	ASSERT_EQ(bss->usdt_rip_args[2], (uintptr_t)add_ptr, "usdt_rip_arg3");
	ASSERT_EQ(bss->usdt_rip_arg_sizes[0], sizeof(char), "usdt_rip_arg1_size");
	ASSERT_EQ(bss->usdt_rip_arg_sizes[1], sizeof(long), "usdt_rip_arg2_size");
	ASSERT_EQ(bss->usdt_rip_arg_sizes[2], sizeof(add_ptr), "usdt_rip_arg3_size");


cleanup:
	test_usdt_o2__destroy(skel);
}



void test_usdt_o2(void)
{
	basic_usdt();
}
