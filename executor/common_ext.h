// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is included into executor and C reproducers and can be used to add
// non-mainline pseudo-syscalls and to provide some other extension points
// w/o changing any other files. See common_ext_example.h for an example implementation.

// Pseudo-syscalls defined in this file should start with syz_ext_.

// This file can also define SYZ_HAVE_SETUP_EXT to 1 and provide
// void setup_ext() function that will be called during VM setup.

// This file can also define SYZ_HAVE_SETUP_EXT_TEST to 1 and provide
// void setup_ext_test() function that will be called during setup of each test process.
#define SYZ_HAVE_SETUP_EXT_TEST 1
static void setup_ext_test(void)
{
	// GTP packets: syz_emit_ethernet writes to syz_tun (src=172.20.20.187, dst=172.20.20.170).
	// Both syz_tun and gtp0 have routes for 172.20.20.0/24.
	// Effective rp_filter = max(all, iface), so we must zero both.
	// Strict rp_filter would DROP if FIB prefers gtp0 for reverse path.
	write_file("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
	write_file("/proc/sys/net/ipv4/conf/syz_tun/rp_filter", "0");
}